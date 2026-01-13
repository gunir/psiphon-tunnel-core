/*
 * Copyright (c) 2015, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package psiphon

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/dsl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

var (
	datastoreServerEntriesBucket                = []byte("serverEntries")
	datastoreServerEntryTagsBucket              = []byte("serverEntryTags")
	datastoreServerEntryTombstoneTagsBucket     = []byte("serverEntryTombstoneTags")
	datastoreUrlETagsBucket                     = []byte("urlETags")
	datastoreKeyValueBucket                     = []byte("keyValues")
	datastoreRemoteServerListStatsBucket        = []byte("remoteServerListStats")
	datastoreFailedTunnelStatsBucket            = []byte("failedTunnelStats")
	datastoreSLOKsBucket                        = []byte("SLOKs")
	datastoreTacticsBucket                      = []byte("tactics")
	datastoreSpeedTestSamplesBucket             = []byte("speedTestSamples")
	datastoreDialParametersBucket               = []byte("dialParameters")
	datastoreNetworkReplayParametersBucket      = []byte("networkReplayParameters")
	datastoreDSLOSLStatesBucket                 = []byte("dslOSLStates")
	datastoreLastConnectedKey                   = "lastConnected"
	datastoreLastServerEntryFilterKey           = []byte("lastServerEntryFilter")
	datastoreAffinityServerEntryIDKey           = []byte("affinityServerEntryID")
	datastoreInproxyCommonCompartmentIDsKey     = []byte("inproxyCommonCompartmentIDs")
	datastorePersistentStatTypeRemoteServerList = string(datastoreRemoteServerListStatsBucket)
	datastorePersistentStatTypeFailedTunnel     = string(datastoreFailedTunnelStatsBucket)
	datastoreCheckServerEntryTagsEndTimeKey     = "checkServerEntryTagsEndTime"
	datastoreDSLLastUntunneledFetchTimeKey      = "dslLastUntunneledDiscoverTime"
	datastoreDSLLastTunneledFetchTimeKey        = "dslLastTunneledDiscoverTime"
	datastoreDSLLastActiveOSLsTimeKey           = "dslLastActiveOSLsTime"

	datastoreServerEntryFetchGCThreshold = 10
	// Add these:
    persistentStatTypes = []string{
        datastorePersistentStatTypeRemoteServerList,
        datastorePersistentStatTypeFailedTunnel,
    }
    persistentStatStateUnreported = []byte{0}
    persistentStatStateReporting  = []byte{1}
)

// DataStore holds the state for a single tunnel's persistent data.
type DataStore struct {
	db                            *datastoreDB
	mutex                         sync.RWMutex
	disableCheckServerEntryTags   atomic.Bool
	datastoreLastServerEntryCount atomic.Int64
}

// NewDataStore opens and initializes a datastore instance for the given config.
func NewDataStore(config *Config) (*DataStore, error) {
	ds := &DataStore{}
	ds.datastoreLastServerEntryCount.Store(-1)

	// datastoreOpenDB is defined in dataStore_bolt.go (or other backend)
	// and must use the directory specified in the config.
	newDB, err := datastoreOpenDB(config.GetDataStoreDirectory(), true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	ds.db = newDB

	err = ds.resetAllPersistentStatsToUnreported()
	if err != nil {
		// Log error but proceed, as this is maintenance
		NoticeWarning("NewDataStore: resetAllPersistentStatsToUnreported failed: %s", err)
	}

	return ds, nil
}

// Close closes the datastore instance.
func (ds *DataStore) Close() {
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	if ds.db != nil {
		err := ds.db.close()
		if err != nil {
			NoticeWarning("failed to close datastore: %s", errors.Trace(err))
		}
		ds.db = nil
	}
}

// GetDataStoreMetrics returns a string logging datastore metrics.
func (ds *DataStore) GetDataStoreMetrics() string {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	if ds.db == nil {
		return ""
	}

	return ds.db.getDataStoreMetrics()
}

// view runs a read-only transaction.
func (ds *DataStore) view(fn func(tx *datastoreTx) error) error {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	if ds.db == nil {
		return errors.TraceNew("datastore not open")
	}

	err := ds.db.view(fn)
	if err != nil {
		err = errors.Trace(err)
	}
	return err
}

// update runs a read-write transaction.
func (ds *DataStore) update(fn func(tx *datastoreTx) error) error {
	ds.mutex.RLock()
	defer ds.mutex.RUnlock()

	if ds.db == nil {
		return errors.TraceNew("database not open")
	}

	err := ds.db.update(fn)
	if err != nil {
		err = errors.Trace(err)
	}
	return err
}

// StoreServerEntry adds the server entry to the datastore.
func (ds *DataStore) StoreServerEntry(
	serverEntryFields protocol.ServerEntryFields,
	replaceIfExists bool) error {

	return errors.Trace(
		ds.storeServerEntry(serverEntryFields, replaceIfExists, nil))
}

func (ds *DataStore) storeServerEntry(
	serverEntryFields protocol.ServerEntryFields,
	replaceIfExists bool,
	additionalUpdates func(tx *datastoreTx, serverEntryID []byte) error) error {

	err := protocol.ValidateServerEntryFields(serverEntryFields)
	if err != nil {
		return errors.Tracef("invalid server entry: %s", err)
	}

	err = ds.update(func(tx *datastoreTx) error {

		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)
		serverEntryTombstoneTags := tx.bucket(datastoreServerEntryTombstoneTagsBucket)

		serverEntryID := []byte(serverEntryFields.GetIPAddress())

		existingConfigurationVersion := -1
		existingData := serverEntries.get(serverEntryID)
		if existingData != nil {
			var existingServerEntry *protocol.ServerEntry
			err := json.Unmarshal(existingData, &existingServerEntry)
			if err == nil {
				existingConfigurationVersion = existingServerEntry.ConfigurationVersion
			}
		}

		configurationVersion := serverEntryFields.GetConfigurationVersion()

		exists := existingConfigurationVersion > -1
		newer := exists && existingConfigurationVersion < configurationVersion
		update := !exists || replaceIfExists || newer

		if !update {
			return nil
		}

		serverEntryTag := serverEntryFields.GetTag()

		if serverEntryTag == "" {
			serverEntryTag = protocol.GenerateServerEntryTag(
				serverEntryFields.GetIPAddress(),
				serverEntryFields.GetWebServerSecret())
			serverEntryFields.SetTag(serverEntryTag)
		}

		serverEntryTagBytes := []byte(serverEntryTag)

		if serverEntryFields.GetLocalSource() == protocol.SERVER_ENTRY_SOURCE_EMBEDDED {
			if serverEntryTombstoneTags.get(serverEntryTagBytes) != nil {
				return nil
			}
		}

		data, err := json.Marshal(serverEntryFields)
		if err != nil {
			return errors.Trace(err)
		}

		err = serverEntries.put(serverEntryID, data)
		if err != nil {
			return errors.Trace(err)
		}

		serverEntryTagRecord, err := setServerEntryTagRecord(
			serverEntryID, configurationVersion)
		if err != nil {
			return errors.Trace(err)
		}

		err = serverEntryTags.put(serverEntryTagBytes, serverEntryTagRecord)
		if err != nil {
			return errors.Trace(err)
		}

		if additionalUpdates != nil {
			err = additionalUpdates(tx, serverEntryID)
			if err != nil {
				return errors.Trace(err)
			}
		}

		NoticeInfo("updated server %s", serverEntryFields.GetDiagnosticID())

		return nil
	})
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// StoreServerEntries stores a list of server entries.
func (ds *DataStore) StoreServerEntries(
	config *Config,
	serverEntries []protocol.ServerEntryFields,
	replaceIfExists bool) error {

	for _, serverEntryFields := range serverEntries {
		err := ds.StoreServerEntry(serverEntryFields, replaceIfExists)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// StreamingStoreServerEntries stores a list of server entries.
func (ds *DataStore) StreamingStoreServerEntries(
	ctx context.Context,
	config *Config,
	serverEntries *protocol.StreamingServerEntryDecoder,
	replaceIfExists bool) error {

	n := 0
	for {
		select {
		case <-ctx.Done():
			return errors.Trace(ctx.Err())
		default:
		}

		serverEntry, err := serverEntries.Next()
		if err != nil {
			return errors.Trace(err)
		}

		if serverEntry == nil {
			return nil
		}

		err = ds.StoreServerEntry(serverEntry, replaceIfExists)
		if err != nil {
			return errors.Trace(err)
		}

		n += 1
		if n == datastoreServerEntryFetchGCThreshold {
			DoGarbageCollection()
			n = 0
		}
	}
}

// ImportEmbeddedServerEntries loads, decodes, and stores a list of server entries.
func (ds *DataStore) ImportEmbeddedServerEntries(
	ctx context.Context,
	config *Config,
	embeddedServerEntryListFilename string,
	embeddedServerEntryList string) error {

	var reader io.Reader

	if embeddedServerEntryListFilename != "" {
		file, err := os.Open(embeddedServerEntryListFilename)
		if err != nil {
			return errors.Trace(err)
		}
		defer file.Close()
		reader = file
	} else {
		reader = strings.NewReader(embeddedServerEntryList)
	}

	err := ds.StreamingStoreServerEntries(
		ctx,
		config,
		protocol.NewStreamingServerEntryDecoder(
			reader,
			common.TruncateTimestampToHour(common.GetCurrentTimestamp()),
			protocol.SERVER_ENTRY_SOURCE_EMBEDDED),
		false)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// PromoteServerEntry sets the server affinity server entry ID.
func (ds *DataStore) PromoteServerEntry(config *Config, ipAddress string) error {
	err := ds.update(func(tx *datastoreTx) error {

		serverEntryID := []byte(ipAddress)

		bucket := tx.bucket(datastoreServerEntriesBucket)
		data := bucket.get(serverEntryID)
		if data == nil {
			NoticeWarning(
				"PromoteServerEntry: ignoring unknown server entry: %s",
				ipAddress)
			return nil
		}

		bucket = tx.bucket(datastoreKeyValueBucket)
		err := bucket.put(datastoreAffinityServerEntryIDKey, serverEntryID)
		if err != nil {
			return errors.Trace(err)
		}

		currentFilter, err := makeServerEntryFilterValue(config)
		if err != nil {
			return errors.Trace(err)
		}

		err = bucket.put(datastoreLastServerEntryFilterKey, currentFilter)
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// DeleteServerEntryAffinity clears server affinity.
func (ds *DataStore) DeleteServerEntryAffinity(ipAddress string) error {
	err := ds.update(func(tx *datastoreTx) error {

		serverEntryID := []byte(ipAddress)

		bucket := tx.bucket(datastoreKeyValueBucket)

		affinityServerEntryID := bucket.get(datastoreAffinityServerEntryIDKey)

		if bytes.Equal(affinityServerEntryID, serverEntryID) {
			err := bucket.delete(datastoreAffinityServerEntryIDKey)
			if err != nil {
				return errors.Trace(err)
			}
			err = bucket.delete(datastoreLastServerEntryFilterKey)
			if err != nil {
				return errors.Trace(err)
			}
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// GetLastServerEntryCount returns a generalized number of server entries.
func (ds *DataStore) GetLastServerEntryCount() int {
	count := int(ds.datastoreLastServerEntryCount.Load())

	if count <= 0 {
		return count
	}

	n := protocol.ServerEntryCountRoundingIncrement
	return ((count + (n - 1)) / n) * n
}

func makeServerEntryFilterValue(config *Config) ([]byte, error) {
	return []byte(config.EgressRegion), nil
}

func (ds *DataStore) hasServerEntryFilterChanged(config *Config) (bool, error) {

	currentFilter, err := makeServerEntryFilterValue(config)
	if err != nil {
		return false, errors.Trace(err)
	}

	changed := false
	err = ds.view(func(tx *datastoreTx) error {

		bucket := tx.bucket(datastoreKeyValueBucket)
		previousFilter := bucket.get(datastoreLastServerEntryFilterKey)

		if previousFilter == nil ||
			!bytes.Equal(previousFilter, currentFilter) {
			changed = true
		}
		return nil
	})
	if err != nil {
		return false, errors.Trace(err)
	}

	return changed, nil
}

// ServerEntryIterator is used to iterate over stored server entries.
type ServerEntryIterator struct {
	config                       *Config
	ds                           *DataStore
	applyServerAffinity          bool
	serverEntryIDs               [][]byte
	serverEntryIndex             int
	isTacticsServerEntryIterator bool
	isTargetServerEntryIterator  bool
	isPruneServerEntryIterator   bool
	hasNextTargetServerEntry     bool
	targetServerEntry            *protocol.ServerEntry
}

// NewServerEntryIterator creates a new ServerEntryIterator.
func NewServerEntryIterator(config *Config) (bool, *ServerEntryIterator, error) {

	if config.TargetServerEntry != "" {
		return newTargetServerEntryIterator(config, false)
	}

	if config.DataStore == nil {
		return false, nil, errors.TraceNew("DataStore not initialized in config")
	}

	filterChanged, err := config.DataStore.hasServerEntryFilterChanged(config)
	if err != nil {
		return false, nil, errors.Trace(err)
	}

	applyServerAffinity := !filterChanged

	iterator := &ServerEntryIterator{
		config:              config,
		ds:                  config.DataStore,
		applyServerAffinity: applyServerAffinity,
	}

	err = iterator.reset(true)
	if err != nil {
		return false, nil, errors.Trace(err)
	}

	return applyServerAffinity, iterator, nil
}

func NewTacticsServerEntryIterator(config *Config) (*ServerEntryIterator, error) {

	if config.TargetServerEntry != "" {
		_, iterator, err := newTargetServerEntryIterator(config, true)
		return iterator, err
	}

	if config.DataStore == nil {
		return nil, errors.TraceNew("DataStore not initialized in config")
	}

	iterator := &ServerEntryIterator{
		config:                       config,
		ds:                           config.DataStore,
		isTacticsServerEntryIterator: true,
	}

	err := iterator.reset(true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return iterator, nil
}

func NewPruneServerEntryIterator(config *Config) (*ServerEntryIterator, error) {

	if config.DataStore == nil {
		return nil, errors.TraceNew("DataStore not initialized in config")
	}

	iterator := &ServerEntryIterator{
		config:                     config,
		ds:                         config.DataStore,
		isPruneServerEntryIterator: true,
	}

	err := iterator.reset(true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return iterator, nil
}

func newTargetServerEntryIterator(config *Config, isTactics bool) (bool, *ServerEntryIterator, error) {

	// Note: TargetServerEntry iterators don't strictly require the DataStore
	// for iteration, but may need it for updating stats later.
	// We assume config.DataStore is available if needed.

	serverEntry, err := protocol.DecodeServerEntry(
		config.TargetServerEntry, config.loadTimestamp, protocol.SERVER_ENTRY_SOURCE_TARGET)
	if err != nil {
		return false, nil, errors.Trace(err)
	}

	if serverEntry.Tag == "" {
		serverEntry.Tag = protocol.GenerateServerEntryTag(
			serverEntry.IpAddress, serverEntry.WebServerSecret)
	}

	if isTactics {
		if len(serverEntry.GetSupportedTacticsProtocols()) == 0 {
			return false, nil, errors.TraceNew("TargetServerEntry does not support tactics protocols")
		}
	} else {
		if config.EgressRegion != "" && serverEntry.Region != config.EgressRegion {
			return false, nil, errors.TraceNew("TargetServerEntry does not support EgressRegion")
		}

		p := config.GetParameters().Get()
		limitTunnelProtocols := p.TunnelProtocols(parameters.LimitTunnelProtocols)
		limitTunnelDialPortNumbers := protocol.TunnelProtocolPortLists(
			p.TunnelProtocolPortLists(parameters.LimitTunnelDialPortNumbers))
		limitQUICVersions := p.QUICVersions(parameters.LimitQUICVersions)

		if len(limitTunnelProtocols) > 0 {
			if len(serverEntry.GetSupportedProtocols(
				conditionallyEnabledComponents{},
				config.UseUpstreamProxy(),
				limitTunnelProtocols,
				limitTunnelDialPortNumbers,
				limitQUICVersions,
				false)) == 0 {
				return false, nil, errors.Tracef(
					"TargetServerEntry does not support LimitTunnelProtocols: %v", limitTunnelProtocols)
			}
		}
	}

	iterator := &ServerEntryIterator{
		isTacticsServerEntryIterator: isTactics,
		isTargetServerEntryIterator:  true,
		hasNextTargetServerEntry:     true,
		targetServerEntry:            serverEntry,
		ds:                           config.DataStore,
	}

	err = iterator.reset(true)
	if err != nil {
		return false, nil, errors.Trace(err)
	}

	NoticeInfo("using TargetServerEntry: %s", serverEntry.GetDiagnosticID())

	return false, iterator, nil
}

func (iterator *ServerEntryIterator) Reset() error {
	return iterator.reset(false)
}

func (iterator *ServerEntryIterator) reset(isInitialRound bool) error {
	iterator.Close()

	if iterator.isTargetServerEntryIterator {
		iterator.hasNextTargetServerEntry = true
		if iterator.ds != nil {
			count := 0
			err := iterator.ds.getBucketKeys(datastoreServerEntriesBucket, func(_ []byte) { count += 1 })
			if err != nil {
				return errors.Trace(err)
			}
			iterator.ds.datastoreLastServerEntryCount.Store(int64(count))
		}
		return nil
	}

	// Note: We skip OpenDataStoreWithoutRetry here as DataStore should be managed by Controller.
	if iterator.ds == nil {
		return errors.TraceNew("iterator has nil datastore")
	}

	var serverEntryIDs [][]byte

	err := iterator.ds.view(func(tx *datastoreTx) error {

		bucket := tx.bucket(datastoreKeyValueBucket)

		serverEntryIDs = make([][]byte, 0)
		shuffleHead := 0

		var affinityServerEntryID []byte

		if !iterator.isPruneServerEntryIterator &&
			isInitialRound &&
			iterator.applyServerAffinity {

			affinityServerEntryID = bucket.get(datastoreAffinityServerEntryIDKey)
			if affinityServerEntryID != nil {
				serverEntryIDs = append(serverEntryIDs, append([]byte(nil), affinityServerEntryID...))
				shuffleHead = 1
			}
		}

		bucket = tx.bucket(datastoreServerEntriesBucket)
		cursor := bucket.cursor()
		for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
			if affinityServerEntryID != nil {
				if bytes.Equal(affinityServerEntryID, key) {
					continue
				}
			}
			serverEntryIDs = append(serverEntryIDs, append([]byte(nil), key...))
		}
		cursor.close()

		iterator.ds.datastoreLastServerEntryCount.Store(int64(len(serverEntryIDs)))

		for i := len(serverEntryIDs) - 1; i > shuffleHead-1; i-- {
			j := prng.Intn(i+1-shuffleHead) + shuffleHead
			serverEntryIDs[i], serverEntryIDs[j] = serverEntryIDs[j], serverEntryIDs[i]
		}

		p := iterator.config.GetParameters().Get()

		if !iterator.isPruneServerEntryIterator &&
			(isInitialRound || p.WeightedCoinFlip(parameters.ReplayLaterRoundMoveToFrontProbability)) &&
			p.Int(parameters.ReplayCandidateCount) != 0 {

			networkID := []byte(iterator.config.GetNetworkID())

			dialParamsBucket := tx.bucket(datastoreDialParametersBucket)
			i := shuffleHead
			j := len(serverEntryIDs) - 1
			for {
				for ; i < j; i++ {
					key := makeDialParametersKey(serverEntryIDs[i], networkID)
					if dialParamsBucket.get(key) == nil {
						break
					}
				}
				for ; i < j; j-- {
					key := makeDialParametersKey(serverEntryIDs[j], networkID)
					if dialParamsBucket.get(key) != nil {
						break
					}
				}
				if i < j {
					serverEntryIDs[i], serverEntryIDs[j] = serverEntryIDs[j], serverEntryIDs[i]
					i++
					j--
				} else {
					break
				}
			}
		}

		return nil
	})
	if err != nil {
		return errors.Trace(err)
	}

	iterator.serverEntryIDs = serverEntryIDs
	iterator.serverEntryIndex = 0

	return nil
}

func (iterator *ServerEntryIterator) Close() {
	iterator.serverEntryIDs = nil
	iterator.serverEntryIndex = 0
}

func (iterator *ServerEntryIterator) Next() (*protocol.ServerEntry, error) {

	var serverEntry *protocol.ServerEntry
	var err error

	defer func() {
		if err != nil {
			iterator.Close()
		}
	}()

	if iterator.isTargetServerEntryIterator {
		if iterator.hasNextTargetServerEntry {
			iterator.hasNextTargetServerEntry = false
			return MakeCompatibleServerEntry(iterator.targetServerEntry), nil
		}
		return nil, nil
	}

	if iterator.ds == nil {
		return nil, errors.TraceNew("iterator has nil datastore")
	}

	for {
		if iterator.serverEntryIndex >= len(iterator.serverEntryIDs) {
			return nil, nil
		}

		serverEntryID := iterator.serverEntryIDs[iterator.serverEntryIndex]
		iterator.serverEntryIndex += 1

		serverEntry = nil
		doDeleteServerEntry := false

		err = iterator.ds.view(func(tx *datastoreTx) error {
			serverEntries := tx.bucket(datastoreServerEntriesBucket)
			value := serverEntries.get(serverEntryID)
			if value == nil {
				return nil
			}

			if iterator.config.ServerEntrySignaturePublicKey != "" {
				var serverEntryFields protocol.ServerEntryFields
				err = json.Unmarshal(value, &serverEntryFields)
				if err != nil {
					doDeleteServerEntry = true
					NoticeWarning("ServerEntryIterator.Next: unmarshal failed: %s", errors.Trace(err))
					return nil
				}

				if serverEntryFields.HasSignature() {
					err = serverEntryFields.VerifySignature(
						iterator.config.ServerEntrySignaturePublicKey)
					if err != nil {
						doDeleteServerEntry = true
						NoticeWarning("ServerEntryIterator.Next: verify signature failed: %s", errors.Trace(err))
						return nil
					}
				}
			}

			err = json.Unmarshal(value, &serverEntry)
			if err != nil {
				serverEntry = nil
				doDeleteServerEntry = true
				NoticeWarning("ServerEntryIterator.Next: unmarshal failed: %s", errors.Trace(err))
				return nil
			}

			return nil
		})
		if err != nil {
			return nil, errors.Trace(err)
		}

		if doDeleteServerEntry {
			err := iterator.ds.deleteServerEntry(iterator.config, serverEntryID)
			if err != nil {
				NoticeWarning("ServerEntryIterator.Next: deleteServerEntry failed: %s", errors.Trace(err))
			}
			continue
		}

		if serverEntry == nil {
			NoticeWarning("ServerEntryIterator.Next: unexpected missing server entry")
			continue
		}

		if serverEntry.Tag == "" {
			serverEntry.Tag = protocol.GenerateServerEntryTag(
				serverEntry.IpAddress, serverEntry.WebServerSecret)

			err = iterator.ds.update(func(tx *datastoreTx) error {
				serverEntries := tx.bucket(datastoreServerEntriesBucket)
				serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)

				value := serverEntries.get(serverEntryID)
				if value == nil {
					return nil
				}

				var serverEntryFields protocol.ServerEntryFields
				err := json.Unmarshal(value, &serverEntryFields)
				if err != nil {
					return errors.Trace(err)
				}

				serverEntryTag := serverEntryFields.GetTag()
				if serverEntryTag != "" {
					return nil
				}

				serverEntryTag = protocol.GenerateServerEntryTag(
					serverEntryFields.GetIPAddress(),
					serverEntryFields.GetWebServerSecret())

				serverEntryFields.SetTag(serverEntryTag)

				jsonServerEntryFields, err := json.Marshal(serverEntryFields)
				if err != nil {
					return errors.Trace(err)
				}

				err = serverEntries.put(serverEntryID, jsonServerEntryFields)
				if err != nil {
					return errors.Trace(err)
				}

				serverEntryTagRecord, err := setServerEntryTagRecord(
					[]byte(serverEntryTag),
					serverEntryFields.GetConfigurationVersion())
				if err != nil {
					return errors.Trace(err)
				}

				err = serverEntryTags.put([]byte(serverEntryTag), serverEntryTagRecord)
				if err != nil {
					return errors.Trace(err)
				}

				return nil
			})

			if err != nil {
				NoticeWarning("ServerEntryIterator.Next: update server entry failed: %s", errors.Trace(err))
			}
		}

		if iterator.serverEntryIndex%datastoreServerEntryFetchGCThreshold == 0 {
			DoGarbageCollection()
		}

		if iterator.isPruneServerEntryIterator {
			break
		} else if iterator.isTacticsServerEntryIterator {
			if len(serverEntry.GetSupportedTacticsProtocols()) > 0 {
				break
			}
		} else {
			if iterator.config.EgressRegion == "" ||
				serverEntry.Region == iterator.config.EgressRegion {
				break
			}
		}
	}

	return MakeCompatibleServerEntry(serverEntry), nil
}

func MakeCompatibleServerEntry(serverEntry *protocol.ServerEntry) *protocol.ServerEntry {
	if len(serverEntry.MeekFrontingAddresses) == 0 && serverEntry.MeekFrontingDomain != "" {
		serverEntry.MeekFrontingAddresses =
			append(serverEntry.MeekFrontingAddresses, serverEntry.MeekFrontingDomain)
	}
	return serverEntry
}

// PruneServerEntry deletes the server entry.
func (ds *DataStore) PruneServerEntry(config *Config, serverEntryTag string) bool {
	pruned, err := ds.pruneServerEntry(config, serverEntryTag)
	if err != nil {
		NoticeWarning(
			"PruneServerEntry failed: %s: %s",
			serverEntryTag, errors.Trace(err))
		return false
	}
	if pruned {
		NoticePruneServerEntry(serverEntryTag)
	}
	return pruned
}

func (ds *DataStore) pruneServerEntry(config *Config, serverEntryTag string) (bool, error) {

	minimumAgeForPruning := config.GetParameters().Get().Duration(
		parameters.ServerEntryMinimumAgeForPruning)

	pruned := false

	err := ds.update(func(tx *datastoreTx) error {

		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)
		serverEntryTombstoneTags := tx.bucket(datastoreServerEntryTombstoneTagsBucket)
		keyValues := tx.bucket(datastoreKeyValueBucket)
		dialParameters := tx.bucket(datastoreDialParametersBucket)

		serverEntryTagBytes := []byte(serverEntryTag)

		serverEntryTagRecord := serverEntryTags.get(serverEntryTagBytes)
		if serverEntryTagRecord == nil {
			return errors.TraceNew("server entry tag not found")
		}

		serverEntryID, _, err := getServerEntryTagRecord(serverEntryTagRecord)
		if err != nil {
			return errors.Trace(err)
		}

		serverEntryJson := serverEntries.get(serverEntryID)
		if serverEntryJson == nil {
			return errors.TraceNew("server entry not found")
		}

		var serverEntry *protocol.ServerEntry
		err = json.Unmarshal(serverEntryJson, &serverEntry)
		if err != nil {
			return errors.Trace(err)
		}

		serverEntryLocalTimestamp, err := time.Parse(time.RFC3339, serverEntry.LocalTimestamp)
		if err != nil {
			return errors.Trace(err)
		}
		if serverEntryLocalTimestamp.Add(minimumAgeForPruning).After(time.Now()) {
			return nil
		}

		doDeleteServerEntry := (serverEntry.Tag == serverEntryTag)

		err = serverEntryTags.delete(serverEntryTagBytes)
		if err != nil {
			return errors.Trace(err)
		}

		if doDeleteServerEntry {
			err = ds.deleteServerEntryHelper(
				config,
				serverEntryID,
				serverEntries,
				keyValues,
				dialParameters)
			if err != nil {
				return errors.Trace(err)
			}
		}

		if serverEntry.LocalSource == protocol.SERVER_ENTRY_SOURCE_EMBEDDED {
			err = serverEntryTombstoneTags.put(serverEntryTagBytes, []byte{1})
			if err != nil {
				return errors.Trace(err)
			}
		}

		pruned = true

		return nil
	})

	return pruned, errors.Trace(err)
}

// DeleteServerEntry deletes the specified server entry.
func (ds *DataStore) DeleteServerEntry(config *Config, ipAddress string) {
	serverEntryID := []byte(ipAddress)
	err := ds.deleteServerEntry(config, serverEntryID)
	if err != nil {
		NoticeWarning("DeleteServerEntry failed: %s", errors.Trace(err))
		return
	}
	NoticeInfo("Server entry deleted")
}

func (ds *DataStore) deleteServerEntry(config *Config, serverEntryID []byte) error {
	return ds.update(func(tx *datastoreTx) error {
		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)
		keyValues := tx.bucket(datastoreKeyValueBucket)
		dialParameters := tx.bucket(datastoreDialParametersBucket)

		err := ds.deleteServerEntryHelper(
			config,
			serverEntryID,
			serverEntries,
			keyValues,
			dialParameters)
		if err != nil {
			return errors.Trace(err)
		}

		var deleteKeys [][]byte
		cursor := serverEntryTags.cursor()
		for key, value := cursor.first(); key != nil; key, value = cursor.next() {
			if bytes.Equal(value, serverEntryID) {
				deleteKeys = append(deleteKeys, key)
			}
		}
		cursor.close()

		for _, deleteKey := range deleteKeys {
			err := serverEntryTags.delete(deleteKey)
			if err != nil {
				return errors.Trace(err)
			}
		}

		return nil
	})
}

func (ds *DataStore) deleteServerEntryHelper(
	config *Config,
	serverEntryID []byte,
	serverEntries *datastoreBucket,
	keyValues *datastoreBucket,
	dialParameters *datastoreBucket) error {

	err := serverEntries.delete(serverEntryID)
	if err != nil {
		return errors.Trace(err)
	}

	affinityServerEntryID := keyValues.get(datastoreAffinityServerEntryIDKey)
	if bytes.Equal(affinityServerEntryID, serverEntryID) {
		err = keyValues.delete(datastoreAffinityServerEntryIDKey)
		if err != nil {
			return errors.Trace(err)
		}
		err = keyValues.delete(datastoreLastServerEntryFilterKey)
		if err != nil {
			return errors.Trace(err)
		}
	}

	foundFirstMatch := false
	var deleteKeys [][]byte
	cursor := dialParameters.cursor()
	for key, _ := cursor.first(); key != nil; key, _ = cursor.next() {
		if bytes.HasPrefix(key, serverEntryID) {
			foundFirstMatch = true
			deleteKeys = append(deleteKeys, key)
		} else if foundFirstMatch {
			break
		}
	}
	cursor.close()

	for _, deleteKey := range deleteKeys {
		err := dialParameters.delete(deleteKey)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// ScanServerEntries iterates over all stored server entries.
func (ds *DataStore) ScanServerEntries(callback func(*protocol.ServerEntry) bool) error {
	err := ds.view(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreServerEntriesBucket)
		cursor := bucket.cursor()
		n := 0

		for key, value := cursor.first(); key != nil; key, value = cursor.next() {
			var serverEntry *protocol.ServerEntry
			err := json.Unmarshal(value, &serverEntry)
			if err != nil {
				NoticeWarning("ScanServerEntries: %s", errors.Trace(err))
				continue
			}

			if !callback(serverEntry) {
				cursor.close()
				return errors.TraceNew("scan cancelled")
			}

			n += 1
			if n == datastoreServerEntryFetchGCThreshold {
				DoGarbageCollection()
				n = 0
			}
		}
		cursor.close()
		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// HasServerEntries returns a bool indicating if the data store contains at least one server entry.
func (ds *DataStore) HasServerEntries() bool {
	hasServerEntries := false
	err := ds.view(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreServerEntriesBucket)
		cursor := bucket.cursor()
		key, _ := cursor.first()
		hasServerEntries = (key != nil)
		cursor.close()
		return nil
	})

	if err != nil {
		NoticeWarning("HasServerEntries failed: %s", errors.Trace(err))
		return false
	}

	return hasServerEntries
}

// CountServerEntries returns a count of stored server entries.
func (ds *DataStore) CountServerEntries() int {
	count := 0
	err := ds.view(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreServerEntriesBucket)
		cursor := bucket.cursor()
		for key, _ := cursor.first(); key != nil; key, _ = cursor.next() {
			count += 1
		}
		cursor.close()
		return nil
	})

	if err != nil {
		NoticeWarning("CountServerEntries failed: %s", err)
		return 0
	}

	return count
}

// SetUrlETag stores an ETag for the specfied URL.
func (ds *DataStore) SetUrlETag(url, etag string) error {
	err := ds.update(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreUrlETagsBucket)
		err := bucket.put([]byte(url), []byte(etag))
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// GetUrlETag retrieves a previously stored an ETag.
func (ds *DataStore) GetUrlETag(url string) (string, error) {
	var etag string
	err := ds.view(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreUrlETagsBucket)
		etag = string(bucket.get([]byte(url)))
		return nil
	})
	if err != nil {
		return "", errors.Trace(err)
	}
	return etag, nil
}

// SetKeyValue stores a key/value pair.
func (ds *DataStore) SetKeyValue(key, value string) error {
	err := ds.update(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreKeyValueBucket)
		err := bucket.put([]byte(key), []byte(value))
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// GetKeyValue retrieves the value for a given key.
func (ds *DataStore) GetKeyValue(key string) (string, error) {
	var value string
	err := ds.view(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreKeyValueBucket)
		value = string(bucket.get([]byte(key)))
		return nil
	})
	if err != nil {
		return "", errors.Trace(err)
	}
	return value, nil
}

// StorePersistentStat adds a new persistent stat record.
func (ds *DataStore) StorePersistentStat(config *Config, statType string, stat []byte) error {
	if !common.Contains(persistentStatTypes, statType) {
		return errors.Tracef("invalid persistent stat type: %s", statType)
	}

	maxStoreRecords := config.GetParameters().Get().Int(
		parameters.PersistentStatsMaxStoreRecords)

	err := ds.update(func(tx *datastoreTx) error {
		bucket := tx.bucket([]byte(statType))

		count := 0
		cursor := bucket.cursor()
		for key, _ := cursor.first(); key != nil; key, _ = cursor.next() {
			count++
		}
		cursor.close()

		if count >= maxStoreRecords {
			return nil
		}

		err := bucket.put(stat, persistentStatStateUnreported)
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// CountUnreportedPersistentStats returns the number of persistent stat records in StateUnreported.
func (ds *DataStore) CountUnreportedPersistentStats() int {
	unreported := 0
	err := ds.view(func(tx *datastoreTx) error {
		for _, statType := range persistentStatTypes {
			bucket := tx.bucket([]byte(statType))
			cursor := bucket.cursor()
			for key, value := cursor.first(); key != nil; key, value = cursor.next() {
				if bytes.Equal(value, persistentStatStateUnreported) {
					unreported++
				}
			}
			cursor.close()
		}
		return nil
	})

	if err != nil {
		NoticeWarning("CountUnreportedPersistentStats failed: %s", err)
		return 0
	}

	return unreported
}

// TakeOutUnreportedPersistentStats returns persistent stats records.
func (ds *DataStore) TakeOutUnreportedPersistentStats(
	config *Config,
	adjustMaxSendBytes int) (map[string][][]byte, int, error) {

	stats := make(map[string][][]byte)
	maxSendBytes := config.GetParameters().Get().Int(
		parameters.PersistentStatsMaxSendBytes)
	maxSendBytes -= adjustMaxSendBytes
	sendBytes := 0

	err := ds.update(func(tx *datastoreTx) error {
		for _, statType := range persistentStatTypes {
			bucket := tx.bucket([]byte(statType))
			var deleteKeys [][]byte
			cursor := bucket.cursor()
			for key, value := cursor.first(); key != nil; key, value = cursor.next() {
				var jsonData interface{}
				err := json.Unmarshal(key, &jsonData)
				if err != nil {
					NoticeWarning("Invalid key in TakeOutUnreportedPersistentStats: %s: %s", string(key), err)
					deleteKeys = append(deleteKeys, key)
					continue
				}

				if bytes.Equal(value, persistentStatStateUnreported) {
					data := make([]byte, len(key))
					copy(data, key)
					if stats[statType] == nil {
						stats[statType] = make([][]byte, 0)
					}
					stats[statType] = append(stats[statType], data)
					sendBytes += len(data)
					if sendBytes >= maxSendBytes {
						break
					}
				}
			}
			cursor.close()

			for _, deleteKey := range deleteKeys {
				_ = bucket.delete(deleteKey)
			}

			for _, key := range stats[statType] {
				err := bucket.put(key, persistentStatStateReporting)
				if err != nil {
					return errors.Trace(err)
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, 0, errors.Trace(err)
	}

	return stats, sendBytes, nil
}

// PutBackUnreportedPersistentStats restores a list of persistent stat records.
func (ds *DataStore) PutBackUnreportedPersistentStats(stats map[string][][]byte) error {
	err := ds.update(func(tx *datastoreTx) error {
		for _, statType := range persistentStatTypes {
			bucket := tx.bucket([]byte(statType))
			for _, key := range stats[statType] {
				err := bucket.put(key, persistentStatStateUnreported)
				if err != nil {
					return errors.Trace(err)
				}
			}
		}
		return nil
	})
	return errors.Trace(err)
}

// ClearReportedPersistentStats deletes a list of persistent stat records.
func (ds *DataStore) ClearReportedPersistentStats(stats map[string][][]byte) error {
	err := ds.update(func(tx *datastoreTx) error {
		for _, statType := range persistentStatTypes {
			bucket := tx.bucket([]byte(statType))
			for _, key := range stats[statType] {
				err := bucket.delete(key)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	return errors.Trace(err)
}

func (ds *DataStore) resetAllPersistentStatsToUnreported() error {
	err := ds.update(func(tx *datastoreTx) error {
		for _, statType := range persistentStatTypes {
			bucket := tx.bucket([]byte(statType))
			resetKeys := make([][]byte, 0)
			cursor := bucket.cursor()
			for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
				resetKeys = append(resetKeys, key)
			}
			cursor.close()
			for _, key := range resetKeys {
				err := bucket.put(key, persistentStatStateUnreported)
				if err != nil {
					return errors.Trace(err)
				}
			}
		}
		return nil
	})
	return errors.Trace(err)
}

// IsCheckServerEntryTagsDue indicates that a new prune check is due.
func (ds *DataStore) IsCheckServerEntryTagsDue(config *Config) bool {
	if ds.disableCheckServerEntryTags.Load() {
		return false
	}

	p := config.GetParameters().Get()
	enabled := p.Bool(parameters.CheckServerEntryTagsEnabled)
	checkPeriod := p.Duration(parameters.CheckServerEntryTagsPeriod)
	p.Close()

	if !enabled {
		return false
	}

	lastEndTime, err := ds.getTimeKeyValue(datastoreCheckServerEntryTagsEndTimeKey)
	if err != nil {
		NoticeWarning("IsCheckServerEntryTagsDue getTimeKeyValue failed: %s", errors.Trace(err))
		ds.disableCheckServerEntryTags.Store(true)
		return false
	}

	return lastEndTime.IsZero() || time.Now().After(lastEndTime.Add(checkPeriod))
}

// UpdateCheckServerEntryTagsEndTime should be called after a prune check is complete.
func (ds *DataStore) UpdateCheckServerEntryTagsEndTime(config *Config, checkCount int, pruneCount int) {
	p := config.GetParameters().Get()
	ratio := p.Float(parameters.CheckServerEntryTagsRepeatRatio)
	minimum := p.Int(parameters.CheckServerEntryTagsRepeatMinimum)
	p.Close()

	if pruneCount >= minimum && ratio > 0 && float64(pruneCount)/float64(checkCount) >= ratio {
		NoticeInfo("UpdateCheckServerEntryTagsEndTime: %d/%d: repeat", pruneCount, checkCount)
		return
	}

	err := ds.setTimeKeyValue(datastoreCheckServerEntryTagsEndTimeKey, time.Now())
	if err != nil {
		NoticeWarning("UpdateCheckServerEntryTagsEndTime setTimeKeyValue failed: %s", errors.Trace(err))
		ds.disableCheckServerEntryTags.Store(true)
		return
	}

	NoticeInfo("UpdateCheckServerEntryTagsEndTime: %d/%d: done", pruneCount, checkCount)
}

// GetCheckServerEntryTags returns a random selection of server entry tags.
func (ds *DataStore) GetCheckServerEntryTags(config *Config) ([]string, int, error) {
	if ds.disableCheckServerEntryTags.Load() {
		return nil, 0, nil
	}

	if !ds.IsCheckServerEntryTagsDue(config) {
		return nil, 0, nil
	}

	p := config.GetParameters().Get()
	maxSendBytes := p.Int(parameters.CheckServerEntryTagsMaxSendBytes)
	maxWorkTime := p.Duration(parameters.CheckServerEntryTagsMaxWorkTime)
	minimumAgeForPruning := p.Duration(parameters.ServerEntryMinimumAgeForPruning)
	p.Close()

	iterator, err := NewPruneServerEntryIterator(config)
	if err != nil {
		return nil, 0, errors.Trace(err)
	}

	var checkTags []string
	bytes := 0
	startWork := time.Now()

	for {
		serverEntry, err := iterator.Next()
		if err != nil {
			return nil, 0, errors.Trace(err)
		}

		if serverEntry == nil {
			break
		}

		serverEntryLocalTimestamp, err := time.Parse(time.RFC3339, serverEntry.LocalTimestamp)
		if err != nil {
			return nil, 0, errors.Trace(err)
		}
		if serverEntryLocalTimestamp.Add(minimumAgeForPruning).After(time.Now()) {
			continue
		}

		checkTags = append(checkTags, serverEntry.Tag)
		bytes += len(serverEntry.Tag) + 3

		if bytes >= maxSendBytes || (maxWorkTime > 0 && time.Since(startWork) > maxWorkTime) {
			break
		}
	}

	return checkTags, bytes, nil
}

// CountSLOKs returns the total number of SLOK records.
func (ds *DataStore) CountSLOKs() int {
	count := 0
	err := ds.view(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSLOKsBucket)
		cursor := bucket.cursor()
		for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
			count++
		}
		cursor.close()
		return nil
	})

	if err != nil {
		NoticeWarning("CountSLOKs failed: %s", err)
		return 0
	}

	return count
}

// DeleteSLOKs deletes all SLOK records.
func (ds *DataStore) DeleteSLOKs() error {
	err := ds.update(func(tx *datastoreTx) error {
		return tx.clearBucket(datastoreSLOKsBucket)
	})
	return errors.Trace(err)
}

// SetSLOK stores a SLOK key.
func (ds *DataStore) SetSLOK(id, slok []byte) (bool, error) {
	var duplicate bool
	err := ds.update(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSLOKsBucket)
		duplicate = bucket.get(id) != nil
		err := bucket.put(id, slok)
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})

	if err != nil {
		return false, errors.Trace(err)
	}

	return duplicate, nil
}

// GetSLOK returns a SLOK key for the specified ID.
func (ds *DataStore) GetSLOK(id []byte) ([]byte, error) {
	var slok []byte
	err := ds.view(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSLOKsBucket)
		value := bucket.get(id)
		if value != nil {
			slok = make([]byte, len(value))
			copy(slok, value)
		}
		return nil
	})

	if err != nil {
		return nil, errors.Trace(err)
	}

	return slok, nil
}

func makeDialParametersKey(serverIPAddress, networkID []byte) []byte {
	return append(append([]byte(nil), serverIPAddress...), networkID...)
}

// SetDialParameters stores dial parameters.
func (ds *DataStore) SetDialParameters(serverIPAddress, networkID string, dialParams *DialParameters) error {
	key := makeDialParametersKey([]byte(serverIPAddress), []byte(networkID))
	data, err := json.Marshal(dialParams)
	if err != nil {
		return errors.Trace(err)
	}
	return ds.setBucketValue(datastoreDialParametersBucket, key, data)
}

// GetDialParameters fetches any dial parameters.
func (ds *DataStore) GetDialParameters(
	config *Config, serverIPAddress, networkID string) (*DialParameters, error) {

	key := makeDialParametersKey([]byte(serverIPAddress), []byte(networkID))
	var dialParams *DialParameters

	err := ds.getBucketValue(
		datastoreDialParametersBucket,
		key,
		func(value []byte) error {
			if value == nil {
				return nil
			}
			err := json.Unmarshal(value, &dialParams)
			if err != nil {
				return errors.Trace(err)
			}
			return nil
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return dialParams, nil
}

// DeleteDialParameters clears any dial parameters.
func (ds *DataStore) DeleteDialParameters(serverIPAddress, networkID string) error {
	key := makeDialParametersKey([]byte(serverIPAddress), []byte(networkID))
	return ds.deleteBucketValue(datastoreDialParametersBucket, key)
}

// TacticsStorer implements tactics.Storer.
type TacticsStorer struct {
	config *Config
}

func (t *TacticsStorer) SetTacticsRecord(networkID string, record []byte) error {
	if t.config.DataStore == nil {
		return errors.TraceNew("DataStore not initialized")
	}
	err := t.config.DataStore.setBucketValue(datastoreTacticsBucket, []byte(networkID), record)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (t *TacticsStorer) GetTacticsRecord(networkID string) ([]byte, error) {
	if t.config.DataStore == nil {
		return nil, errors.TraceNew("DataStore not initialized")
	}
	value, err := t.config.DataStore.copyBucketValue(datastoreTacticsBucket, []byte(networkID))
	if err != nil {
		return nil, errors.Trace(err)
	}
	return value, nil
}

func (t *TacticsStorer) SetSpeedTestSamplesRecord(networkID string, record []byte) error {
	if t.config.DataStore == nil {
		return errors.TraceNew("DataStore not initialized")
	}
	err := t.config.DataStore.setBucketValue(datastoreSpeedTestSamplesBucket, []byte(networkID), record)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (t *TacticsStorer) GetSpeedTestSamplesRecord(networkID string) ([]byte, error) {
	if t.config.DataStore == nil {
		return nil, errors.TraceNew("DataStore not initialized")
	}
	value, err := t.config.DataStore.copyBucketValue(datastoreSpeedTestSamplesBucket, []byte(networkID))
	if err != nil {
		return nil, errors.Trace(err)
	}
	return value, nil
}

// GetTacticsStorer creates a TacticsStorer.
func GetTacticsStorer(config *Config) *TacticsStorer {
	return &TacticsStorer{config: config}
}

// GetAffinityServerEntryAndDialParameters fetches the current affinity server entry.
func (ds *DataStore) GetAffinityServerEntryAndDialParameters(
	networkID string) (protocol.ServerEntryFields, *DialParameters, error) {

	var serverEntryFields protocol.ServerEntryFields
	var dialParams *DialParameters

	err := ds.view(func(tx *datastoreTx) error {

		keyValues := tx.bucket(datastoreKeyValueBucket)
		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		dialParameters := tx.bucket(datastoreDialParametersBucket)

		affinityServerEntryID := keyValues.get(datastoreAffinityServerEntryIDKey)
		if affinityServerEntryID == nil {
			return errors.TraceNew("no affinity server available")
		}

		serverEntryRecord := serverEntries.get(affinityServerEntryID)
		if serverEntryRecord == nil {
			return errors.TraceNew("affinity server entry not found")
		}

		err := json.Unmarshal(
			serverEntryRecord,
			&serverEntryFields)
		if err != nil {
			return errors.Trace(err)
		}

		dialParamsKey := makeDialParametersKey(
			[]byte(serverEntryFields.GetIPAddress()),
			[]byte(networkID))

		dialParamsRecord := dialParameters.get(dialParamsKey)
		if dialParamsRecord != nil {
			err := json.Unmarshal(dialParamsRecord, &dialParams)
			if err != nil {
				return errors.Trace(err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return serverEntryFields, dialParams, nil
}

// GetSignedServerEntryFields loads the raw JSON server entry fields.
func (ds *DataStore) GetSignedServerEntryFields(ipAddress string) (protocol.ServerEntryFields, error) {

	var serverEntryFields protocol.ServerEntryFields

	err := ds.view(func(tx *datastoreTx) error {
		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		key := []byte(ipAddress)
		serverEntryRecord := serverEntries.get(key)
		if serverEntryRecord == nil {
			return errors.TraceNew("server entry not found")
		}
		err := json.Unmarshal(
			serverEntryRecord,
			&serverEntryFields)
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = serverEntryFields.ToSignedFields()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return serverEntryFields, nil
}

// StoreInproxyCommonCompartmentIDs stores a list of in-proxy common compartment IDs.
func (ds *DataStore) StoreInproxyCommonCompartmentIDs(compartmentIDs []string) error {
	value, err := json.Marshal(compartmentIDs)
	if err != nil {
		return errors.Trace(err)
	}
	err = ds.setBucketValue(
		datastoreKeyValueBucket,
		datastoreInproxyCommonCompartmentIDsKey,
		value)
	return errors.Trace(err)
}

// LoadInproxyCommonCompartmentIDs returns the list of known in-proxy common compartment IDs.
func (ds *DataStore) LoadInproxyCommonCompartmentIDs() ([]string, error) {
	var compartmentIDs []string
	err := ds.getBucketValue(
		datastoreKeyValueBucket,
		datastoreInproxyCommonCompartmentIDsKey,
		func(value []byte) error {
			if value == nil {
				return nil
			}
			err := json.Unmarshal(value, &compartmentIDs)
			if err != nil {
				return errors.Trace(err)
			}
			return nil
		})
	if err != nil {
		return nil, errors.Trace(err)
	}
	return compartmentIDs, nil
}

func makeNetworkReplayParametersKey[R any](networkID, replayID string) []byte {
	var t *R
	key := append(append([]byte(nil), []byte(networkID)...), 0)
	key = append(append(key, []byte(fmt.Sprintf("%T", t)[1:])...), 0)
	key = append(key, []byte(replayID)...)
	return key
}

// SetNetworkReplayParameters stores replay parameters.
func (ds *DataStore) SetNetworkReplayParameters(networkID, replayID string, replayParams interface{}) error {
	// Note: generic [R any] methods can't be simple receiver methods easily if they were generic functions before
	// without creating generic types. However, we can keep them as methods if we define them correctly.
	// For simplicity in this conversion, we assume the caller will instantiate the generic method on ds.
	// But Go generics on methods are only allowed if the type is generic. 
	// The original code used generic functions. We can keep them as generic functions taking *DataStore.
	// OR we assume the user's Go version supports it or we adapt.
	// Since the prompt asks to modify dataStore.go, and we made DataStore a struct, let's keep these
	// as functions that take *DataStore to support generics properly if needed, or if Go allows method generics.
	// Go 1.18+ allows generic methods only on generic types. DataStore is not generic.
	// So we CANNOT have `func (ds *DataStore) SetNetworkReplayParameters[R any]...`.
	// We MUST keep them as standalone functions accepting `ds *DataStore`.
	// However, the previous patterns were converting to methods.
	// Let's implement them as standalone functions taking *DataStore.
	return errors.TraceNew("Not implemented as method due to Go generics limitation on non-generic structs. Use standalone function.")
}

// Standalone generic functions for NetworkReplayParameters to support generics on non-generic DataStore struct.

func SetNetworkReplayParameters[R any](ds *DataStore, networkID, replayID string, replayParams *R) error {
	key := makeNetworkReplayParametersKey[R](networkID, replayID)
	data, err := json.Marshal(replayParams)
	if err != nil {
		return errors.Trace(err)
	}
	return ds.setBucketValue(datastoreNetworkReplayParametersBucket, key, data)
}

func SelectCandidateWithNetworkReplayParameters[C, R any](
	ds *DataStore,
	networkID string,
	selectFirstCandidate bool,
	candidates []*C,
	getReplayID func(*C) string,
	isValidReplay func(*C, *R) bool) (*C, *R, error) {

	if len(candidates) < 1 {
		return nil, nil, errors.TraceNew("no candidates")
	}

	candidate := candidates[0]
	var replay *R

	err := ds.update(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreNetworkReplayParametersBucket)
		for _, c := range candidates {
			key := makeNetworkReplayParametersKey[R](networkID, getReplayID(c))
			value := bucket.get(key)
			if value == nil {
				continue
			}
			var r *R
			err := json.Unmarshal(value, &r)
			if err != nil {
				NoticeWarning(
					"SelectCandidateWithNetworkReplayParameters: unmarshal failed: %s",
					errors.Trace(err))
				_ = bucket.delete(key)
				continue
			}
			if isValidReplay(c, r) {
				candidate = c
				replay = r
				return nil
			} else if selectFirstCandidate {
				return nil
			} else {
				_ = bucket.delete(key)
				continue
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return candidate, replay, nil
}

func DeleteNetworkReplayParameters[R any](ds *DataStore, networkID, replayID string) error {
	key := makeNetworkReplayParametersKey[R](networkID, replayID)
	return ds.deleteBucketValue(datastoreNetworkReplayParametersBucket, key)
}

// DSLGetLastUntunneledFetchTime returns the timestamp of the last successfully completed untunneled DSL fetch.
func (ds *DataStore) DSLGetLastUntunneledFetchTime() (time.Time, error) {
	value, err := ds.getTimeKeyValue(datastoreDSLLastUntunneledFetchTimeKey)
	return value, errors.Trace(err)
}

// DSLSetLastUntunneledFetchTime sets the timestamp of the most recent successfully completed untunneled DSL fetch.
func (ds *DataStore) DSLSetLastUntunneledFetchTime(time time.Time) error {
	err := ds.setTimeKeyValue(datastoreDSLLastUntunneledFetchTimeKey, time)
	return errors.Trace(err)
}

// DSLGetLastTunneledFetchTime returns the timestamp of the last successfully completed tunneled DSL fetch.
func (ds *DataStore) DSLGetLastTunneledFetchTime() (time.Time, error) {
	value, err := ds.getTimeKeyValue(datastoreDSLLastTunneledFetchTimeKey)
	return value, errors.Trace(err)
}

// DSLSetLastTunneledFetchTime sets the timestamp of the most recent successfully completed untunneled DSL fetch.
func (ds *DataStore) DSLSetLastTunneledFetchTime(time time.Time) error {
	err := ds.setTimeKeyValue(datastoreDSLLastTunneledFetchTimeKey, time)
	return errors.Trace(err)
}

func dslLookupServerEntry(
	tx *datastoreTx,
	tag dsl.ServerEntryTag,
	version int) ([]byte, error) {

	serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)
	serverEntryTagRecord := serverEntryTags.get(tag)
	if serverEntryTagRecord == nil {
		return nil, nil
	}

	serverEntryID, configurationVersion, err := getServerEntryTagRecord(serverEntryTagRecord)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if configurationVersion != version {
		return nil, nil
	}

	return serverEntryID, nil
}

func dslPrioritizeDialServerEntry(
	tx *datastoreTx,
	networkID string,
	serverEntryID []byte) error {

	dialParamsBucket := tx.bucket(datastoreDialParametersBucket)
	key := makeDialParametersKey(serverEntryID, []byte(networkID))

	if dialParamsBucket.get(key) != nil {
		return nil
	}

	dialParams := &DialParameters{
		DSLPendingPrioritizeDial: true,
	}

	record, err := json.Marshal(dialParams)
	if err != nil {
		return errors.Trace(err)
	}

	err = dialParamsBucket.put(key, record)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// DSLHasServerEntry returns whether the datastore contains the server entry.
func (ds *DataStore) DSLHasServerEntry(
	tag dsl.ServerEntryTag,
	version int,
	prioritizeDial bool,
	networkID string) bool {

	hasServerEntry := false
	var err error

	if !prioritizeDial {
		err = ds.view(func(tx *datastoreTx) error {
			serverEntryID, err := dslLookupServerEntry(tx, tag, version)
			if err != nil {
				return errors.Trace(err)
			}
			hasServerEntry = (serverEntryID != nil)
			return nil
		})
	} else {
		err = ds.update(func(tx *datastoreTx) error {
			serverEntryID, err := dslLookupServerEntry(tx, tag, version)
			if err != nil {
				return errors.Trace(err)
			}
			hasServerEntry = (serverEntryID != nil)
			if hasServerEntry {
				err := dslPrioritizeDialServerEntry(tx, networkID, serverEntryID)
				if err != nil {
					return errors.Trace(err)
				}
			}
			return nil
		})
	}

	if err != nil {
		NoticeWarning("DSLHasServerEntry failed: %s", errors.Trace(err))
		return false
	}

	return hasServerEntry
}

// DSLStoreServerEntry adds the server entry to the datastore.
func (ds *DataStore) DSLStoreServerEntry(
	serverEntrySignaturePublicKey string,
	packedServerEntryFields protocol.PackedServerEntryFields,
	source string,
	prioritizeDial bool,
	networkID string) error {

	serverEntryFields, err := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
	if err != nil {
		return errors.Trace(err)
	}

	err = serverEntryFields.VerifySignature(serverEntrySignaturePublicKey)
	if err != nil {
		return errors.Trace(err)
	}

	serverEntryFields.SetLocalSource(source)
	serverEntryFields.SetLocalTimestamp(common.TruncateTimestampToHour(common.GetCurrentTimestamp()))

	err = protocol.ValidateServerEntryFields(serverEntryFields)
	if err != nil {
		return errors.Trace(err)
	}

	var additionalUpdates func(tx *datastoreTx, serverEntryID []byte) error
	if prioritizeDial {
		additionalUpdates = func(tx *datastoreTx, serverEntryID []byte) error {
			err := dslPrioritizeDialServerEntry(tx, networkID, serverEntryID)
			if err != nil {
				return errors.Trace(err)
			}
			return nil
		}
	}

	err = ds.storeServerEntry(serverEntryFields, true, additionalUpdates)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// DSLGetLastActiveOSLsTime returns the timestamp of the last successfully completed active OSL check.
func (ds *DataStore) DSLGetLastActiveOSLsTime() (time.Time, error) {
	value, err := ds.getTimeKeyValue(datastoreDSLLastActiveOSLsTimeKey)
	return value, errors.Trace(err)
}

// DSLSetLastActiveOSLsTime sets the timestamp of the most recent successfully completed active OSL check.
func (ds *DataStore) DSLSetLastActiveOSLsTime(time time.Time) error {
	err := ds.setTimeKeyValue(datastoreDSLLastActiveOSLsTimeKey, time)
	return errors.Trace(err)
}

// DSLKnownOSLIDs returns the set of known OSL IDs.
func (ds *DataStore) DSLKnownOSLIDs() ([]dsl.OSLID, error) {
	IDs := []dsl.OSLID{}
	err := ds.getBucketKeys(datastoreDSLOSLStatesBucket, func(key []byte) {
		IDs = append(IDs, append([]byte(nil), key...))
	})
	if err != nil {
		return nil, errors.Trace(err)
	}
	return IDs, nil
}

// DSLGetOSLState gets the current OSL state.
func (ds *DataStore) DSLGetOSLState(ID dsl.OSLID) ([]byte, error) {
	state, err := ds.copyBucketValue(datastoreDSLOSLStatesBucket, ID)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return state, nil
}

// DSLStoreOSLState sets the OSL state.
func (ds *DataStore) DSLStoreOSLState(ID dsl.OSLID, state []byte) error {
	err := ds.setBucketValue(datastoreDSLOSLStatesBucket, ID, state)
	return errors.Trace(err)
}

// DSLDeleteOSLState deletes the specified OSL state.
func (ds *DataStore) DSLDeleteOSLState(ID dsl.OSLID) error {
	err := ds.deleteBucketValue(datastoreDSLOSLStatesBucket, ID)
	return errors.Trace(err)
}

func (ds *DataStore) setTimeKeyValue(key string, timevalue time.Time) error {
	err := ds.SetKeyValue(key, timevalue.Format(time.RFC3339))
	return errors.Trace(err)
}

func (ds *DataStore) getTimeKeyValue(key string) (time.Time, error) {
	value, err := ds.GetKeyValue(key)
	if err != nil {
		return time.Time{}, errors.Trace(err)
	}
	if value == "" {
		return time.Time{}, nil
	}
	timeValue, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.Trace(err)
	}
	return timeValue, nil
}

func (ds *DataStore) setBucketValue(bucket, key, value []byte) error {
	err := ds.update(func(tx *datastoreTx) error {
		b := tx.bucket(bucket)
		err := b.put(key, value)
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})
	return errors.Trace(err)
}

func (ds *DataStore) getBucketValue(bucket, key []byte, valueCallback func([]byte) error) error {
	err := ds.view(func(tx *datastoreTx) error {
		b := tx.bucket(bucket)
		value := b.get(key)
		return valueCallback(value)
	})
	return errors.Trace(err)
}

func (ds *DataStore) deleteBucketValue(bucket, key []byte) error {
	err := ds.update(func(tx *datastoreTx) error {
		b := tx.bucket(bucket)
		return b.delete(key)
	})
	return errors.Trace(err)
}

func (ds *DataStore) copyBucketValue(bucket, key []byte) ([]byte, error) {
	var valueCopy []byte
	err := ds.getBucketValue(bucket, key, func(value []byte) error {
		if value != nil {
			valueCopy = make([]byte, len(value))
			copy(valueCopy, value)
		}
		return nil
	})
	return valueCopy, err
}

func (ds *DataStore) getBucketKeys(bucket []byte, keyCallback func([]byte)) error {
	err := ds.view(func(tx *datastoreTx) error {
		b := tx.bucket(bucket)
		cursor := b.cursor()
		for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
			keyCallback(key)
		}
		cursor.close()
		return nil
	})
	return errors.Trace(err)
}

func setServerEntryTagRecord(serverEntryID []byte, configurationVersion int) ([]byte, error) {
	var delimiter = [1]byte{0}
	if bytes.Contains(serverEntryID, delimiter[:]) {
		return nil, errors.TraceNew("invalid serverEntryID")
	}
	if configurationVersion < 0 || configurationVersion >= math.MaxInt32 {
		return nil, errors.TraceNew("invalid configurationVersion")
	}
	var version [4]byte
	binary.LittleEndian.PutUint32(version[:], uint32(configurationVersion))
	return append(append(serverEntryID, delimiter[:]...), version[:]...), nil
}

func getServerEntryTagRecord(record []byte) ([]byte, int, error) {
	var delimiter = [1]byte{0}
	i := bytes.Index(record, delimiter[:])
	if i == -1 {
		return record, 0, nil
	}
	i += 1
	if len(record)-i != 4 {
		return nil, 0, errors.TraceNew("invalid configurationVersion")
	}
	configurationVersion := binary.LittleEndian.Uint32(record[i:])
	return record[:i-1], int(configurationVersion), nil
}