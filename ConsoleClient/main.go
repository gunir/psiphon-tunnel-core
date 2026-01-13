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

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
)

func main() {

	// Define command-line parameters

	var configFilename string
	flag.StringVar(&configFilename, "config", "", "configuration input file (can also be provided as trailing arguments)")

	var dataRootDirectory string
	flag.StringVar(&dataRootDirectory, "dataRootDirectory", "", "directory where persistent files will be stored (overrides config)")

	var embeddedServerEntryListFilename string
	flag.StringVar(&embeddedServerEntryListFilename, "serverList", "", "embedded server entry list input file")

	var formatNotices bool
	flag.BoolVar(&formatNotices, "formatNotices", false, "emit notices in human-readable format")

	var interfaceName string
	flag.StringVar(&interfaceName, "listenInterface", "", "bind local proxies to specified interface")

	var versionDetails bool
	flag.BoolVar(&versionDetails, "version", false, "print build information and exit")
	flag.BoolVar(&versionDetails, "v", false, "print build information and exit")

	var feedbackUpload bool
	flag.BoolVar(&feedbackUpload, "feedbackUpload", false,
		"Run in feedback upload mode to send a feedback package to Psiphon Inc.\n"+
			"The feedback package will be read as a UTF-8 encoded string from stdin.\n"+
			"Informational notices will be written to stdout. If the upload succeeds,\n"+
			"the process will exit with status code 0; otherwise, the process will\n"+
			"exit with status code 1. A feedback compatible config must be specified\n"+
			"with the \"-config\" flag. Config must be provided by Psiphon Inc.")

	var feedbackUploadPath string
	flag.StringVar(&feedbackUploadPath, "feedbackUploadPath", "",
		"The path at which to upload the feedback package when the \"-feedbackUpload\"\n"+
			"flag is provided. Must be provided by Psiphon Inc.")

	var tunDevice, tunBindInterface, tunDNSServers string
	if tun.IsSupported() {
		flag.StringVar(&tunDevice, "tunDevice", "", "run packet tunnel for specified tun device (applies to first config only)")
		flag.StringVar(&tunBindInterface, "tunBindInterface", tun.DEFAULT_PUBLIC_INTERFACE_NAME, "bypass tun device via specified interface")
		flag.StringVar(&tunDNSServers, "tunDNSServers", "8.8.8.8,8.8.4.4", "Comma-delimited list of tun bypass DNS server IP addresses")
	}

	var noticeFilename string
	flag.StringVar(&noticeFilename, "notices", "", "notices output file (defaults to stderr)")

	var useNoticeFiles bool
	useNoticeFilesUsage := fmt.Sprintf("output homepage notices and rotating notices to <dataRootDirectory>/%s and <dataRootDirectory>/%s respectively", psiphon.HomepageFilename, psiphon.NoticesFilename)
	flag.BoolVar(&useNoticeFiles, "useNoticeFiles", false, useNoticeFilesUsage)

	var rotatingFileSize int
	flag.IntVar(&rotatingFileSize, "rotatingFileSize", 1<<20, "rotating notices file size")

	var rotatingSyncFrequency int
	flag.IntVar(&rotatingSyncFrequency, "rotatingSyncFrequency", 100, "rotating notices file sync frequency")

	flag.Parse()

	if versionDetails {
		b := buildinfo.GetBuildInfo()
		fmt.Printf(
			"Psiphon Console Client\n  Build Date: %s\n  Built With: %s\n  Repository: %s\n  Revision: %s\n",
			b.BuildDate, b.GoVersion, b.BuildRepo, b.BuildRev)
		os.Exit(0)
	}

	// Initialize notice output

	var noticeWriter io.Writer
	noticeWriter = os.Stderr

	if noticeFilename != "" {
		noticeFile, err := os.OpenFile(noticeFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Printf("error opening notice file: %s\n", err)
			os.Exit(1)
		}
		defer noticeFile.Close()
		noticeWriter = noticeFile
	}

	if formatNotices {
		noticeWriter = psiphon.NewNoticeConsoleRewriter(noticeWriter)
	}
	err := psiphon.SetNoticeWriter(noticeWriter)
	if err != nil {
		fmt.Printf("error setting notice writer: %s\n", err)
		os.Exit(1)
	}
	defer psiphon.ResetNoticeWriter()

	// Collect configuration files.
	// We allow -config flag AND trailing arguments to support:
	// ./psiphon -config c1 c2 c3
	var configFiles []string
	if configFilename != "" {
		configFiles = append(configFiles, configFilename)
	}
	configFiles = append(configFiles, flag.Args()...)

	if len(configFiles) == 0 {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("at least one configuration file is required")
		os.Exit(1)
	}

	// Handle Feedback mode (Single config only)
	if feedbackUpload {
		if len(configFiles) > 1 {
			psiphon.NoticeError("feedback upload mode supports only a single configuration file")
			os.Exit(1)
		}
		runFeedbackWorker(configFiles[0], feedbackUploadPath, dataRootDirectory)
		return
	}

	// Multi-Tunnel Mode
	runMultiTunnels(
		configFiles,
		dataRootDirectory,
		embeddedServerEntryListFilename,
		interfaceName,
		useNoticeFiles,
		rotatingFileSize,
		rotatingSyncFrequency,
		tunDevice,
		tunBindInterface,
		tunDNSServers,
	)
}

func runFeedbackWorker(configPath, feedbackUploadPath, dataRootDirectory string) {
	configFileContents, err := ioutil.ReadFile(configPath)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error loading configuration file: %s", err)
		os.Exit(1)
	}
	config, err := psiphon.LoadConfig(configFileContents)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error processing configuration file: %s", err)
		os.Exit(1)
	}

	if dataRootDirectory != "" {
		config.DataRootDirectory = dataRootDirectory
	}

	// Note: For feedback, we don't necessarily need the full NewController DB init
	// if SendFeedback manages transient DBs, but following the new pattern,
	// we assume SendFeedback might need looking into.
	// Based on original code: "The datastore is not opened here... because it is opened/closed transiently in the psiphon.SendFeedback operation."
	// We keep existing behavior for feedback.

	err = config.Commit(true)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error committing config: %s", err)
		os.Exit(1)
	}

	psiphon.NoticeBuildInfo()

	worker := &FeedbackWorker{
		config:             config,
		feedbackUploadPath: feedbackUploadPath,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := worker.Init(ctx, config); err != nil {
		psiphon.NoticeError("error in init: %s", err)
		os.Exit(1)
	}

	if err := worker.Run(ctx); err != nil {
		psiphon.NoticeError("%s", err)
		os.Exit(1)
	}
}

func runMultiTunnels(
	configFiles []string,
	dataRootDirectoryOverride string,
	embeddedServerEntryListFilename string,
	interfaceName string,
	useNoticeFiles bool,
	rotatingFileSize int,
	rotatingSyncFrequency int,
	tunDevice, tunBindInterface, tunDNSServers string) {

	// Global Context
	workCtx, stopWork := context.WithCancel(context.Background())
	defer stopWork()

	var wg sync.WaitGroup

	for i, configPath := range configFiles {
		// Load Config
		configFileContents, err := ioutil.ReadFile(configPath)
		if err != nil {
			psiphon.SetEmitDiagnosticNotices(true, false)
			psiphon.NoticeError("[%s] error loading configuration file: %s", configPath, err)
			continue // Skip bad config, try others
		}

		config, err := psiphon.LoadConfig(configFileContents)
		if err != nil {
			psiphon.SetEmitDiagnosticNotices(true, false)
			psiphon.NoticeError("[%s] error processing configuration file: %s", configPath, err)
			continue
		}

		// Apply Overrides
		if dataRootDirectoryOverride != "" {
			// If running multiple configs, overriding them all to the SAME directory is dangerous
			// unless they have distinct sub-paths inside (which isn't standard).
			// We warn if multiple configs share the same root override.
			if len(configFiles) > 1 {
				psiphon.NoticeWarning("[%s] Warning: Shared dataRootDirectory override used for multiple configs. Database locking conflicts may occur.", configPath)
			}
			config.DataRootDirectory = dataRootDirectoryOverride
		}

		if interfaceName != "" {
			config.ListenInterface = interfaceName
		}

		if useNoticeFiles {
			config.UseNoticeFiles = &psiphon.UseNoticeFiles{
				RotatingFileSize:      rotatingFileSize,
				RotatingSyncFrequency: rotatingSyncFrequency,
			}
		}

		// Configure Packet Tunnel (Only for the first config to avoid contention)
		if i == 0 && tun.IsSupported() && tunDevice != "" {
			tunDeviceFile, err := configurePacketTunnel(
				config, tunDevice, tunBindInterface, strings.Split(tunDNSServers, ","))
			if err != nil {
				psiphon.SetEmitDiagnosticNotices(true, false)
				psiphon.NoticeError("[%s] error configuring packet tunnel: %s", configPath, err)
				os.Exit(1)
			}
			// Keep file open for lifetime of process
			defer tunDeviceFile.Close()
		}

		// Commit Config
		err = config.Commit(true)
		if err != nil {
			psiphon.SetEmitDiagnosticNotices(true, false)
			psiphon.NoticeError("[%s] error committing config: %s", configPath, err)
			continue
		}

		// Initialize Worker
		worker := &TunnelWorker{
			embeddedServerEntryListFilename: embeddedServerEntryListFilename,
			configLabel:                     configPath,
		}

		err = worker.Init(workCtx, config)
		if err != nil {
			psiphon.NoticeError("[%s] error in init: %s", configPath, err)
			continue
		}

		// Run Worker
		wg.Add(1)
		go func(w *TunnelWorker) {
			defer wg.Done()
			if err := w.Run(workCtx); err != nil {
				psiphon.NoticeError("[%s] worker exited with error: %s", w.configLabel, err)
			}
		}(worker)
	}

	psiphon.NoticeBuildInfo()

	// Handle Signals
	systemStopSignal := make(chan os.Signal, 1)
	signal.Notify(systemStopSignal, os.Interrupt, syscall.SIGTERM)
	writeProfilesSignal := makeSIGUSR2Channel()

	psiphon.NoticeInfo("All tunnels started. Press Ctrl+C to stop.")

	// Wait loop
	for {
		select {
		case <-writeProfilesSignal:
			psiphon.NoticeInfo("write profiles")
			profileSampleDurationSeconds := 5
			// Note: This writes profiles to the first available DataRoot if multiple are used,
			// or we just pick one. `common.WriteRuntimeProfiles` takes a directory.
			// We'll use the override if set, or just skip complexity for now.
			if dataRootDirectoryOverride != "" {
				common.WriteRuntimeProfiles(
					psiphon.NoticeCommonLogger(false),
					dataRootDirectoryOverride,
					"",
					profileSampleDurationSeconds,
					profileSampleDurationSeconds)
			} else {
				psiphon.NoticeInfo("write profiles skipped (ambiguous data directory)")
			}

		case <-systemStopSignal:
			psiphon.NoticeInfo("shutdown by system")
			stopWork() // Cancel context for all workers
			wg.Wait()  // Wait for all to finish
			return
		}
	}
}

func configurePacketTunnel(
	config *psiphon.Config,
	tunDevice string,
	tunBindInterface string,
	tunDNSServers []string) (*os.File, error) {

	file, _, err := tun.OpenTunDevice(tunDevice)
	if err != nil {
		return nil, errors.Trace(err)
	}

	provider := &tunProvider{
		bindInterface: tunBindInterface,
		dnsServers:    tunDNSServers,
	}

	config.PacketTunnelTunFileDescriptor = int(file.Fd())
	config.DeviceBinder = provider
	config.DNSServerGetter = provider

	return file, nil
}

type tunProvider struct {
	bindInterface string
	dnsServers    []string
}

// BindToDevice implements the psiphon.DeviceBinder interface.
func (p *tunProvider) BindToDevice(fileDescriptor int) (string, error) {
	return p.bindInterface, tun.BindToDevice(fileDescriptor, p.bindInterface)
}

// GetDNSServers implements the psiphon.DNSServerGetter interface.
func (p *tunProvider) GetDNSServers() []string {
	return p.dnsServers
}

// Worker protocol implementation used for tunnel mode.
type TunnelWorker struct {
	embeddedServerEntryListFilename string
	embeddedServerListWaitGroup     *sync.WaitGroup
	controller                      *psiphon.Controller
	configLabel                     string
}

// Init implements the Worker interface.
func (w *TunnelWorker) Init(ctx context.Context, config *psiphon.Config) error {

	// 1. Create Controller
	// This now initializes the unique DataStore for this config.
	controller, err := psiphon.NewController(config)
	if err != nil {
		return errors.Trace(err)
	}
	w.controller = controller

	// 2. Import Embedded Servers
	// We must use the DataStore instance attached to the config.
	if w.embeddedServerEntryListFilename != "" {
		w.embeddedServerListWaitGroup = new(sync.WaitGroup)
		w.embeddedServerListWaitGroup.Add(1)
		go func() {
			defer w.embeddedServerListWaitGroup.Done()

			// UPDATED: Call method on the specific DataStore instance
			if config.DataStore != nil {
				err := config.DataStore.ImportEmbeddedServerEntries(
					ctx,
					config,
					w.embeddedServerEntryListFilename,
					"")

				if err != nil {
					psiphon.NoticeError("[%s] error importing embedded server entry list: %s", w.configLabel, err)
				}
			}
		}()

		// UPDATED: Call method on the specific DataStore instance
		if config.DataStore != nil && !config.DataStore.HasServerEntries() {
			psiphon.NoticeInfo("[%s] awaiting embedded server entry list import", w.configLabel)
			w.embeddedServerListWaitGroup.Wait()
		}
	}

	return nil
}

// Run implements the Worker interface.
func (w *TunnelWorker) Run(ctx context.Context) error {
	// UPDATED: No global CloseDataStore. The Controller handles closing its own DataStore.
	if w.embeddedServerListWaitGroup != nil {
		defer w.embeddedServerListWaitGroup.Wait()
	}

	w.controller.Run(ctx)
	return nil
}

// FeedbackWorker is the Worker protocol implementation used for feedback
// upload mode.
type FeedbackWorker struct {
	config             *psiphon.Config
	feedbackUploadPath string
}

// Init implements the Worker interface.
func (f *FeedbackWorker) Init(ctx context.Context, config *psiphon.Config) error {
	f.config = config
	return nil
}

// Run implements the Worker interface.
func (f *FeedbackWorker) Run(ctx context.Context) error {
	diagnostics, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return errors.TraceMsg(err, "FeedbackUpload: read stdin failed")
	}

	if len(diagnostics) == 0 {
		return errors.TraceNew("FeedbackUpload: error zero bytes of diagnostics read from stdin")
	}

	err = psiphon.SendFeedback(ctx, f.config, string(diagnostics), f.feedbackUploadPath)
	if err != nil {
		return errors.TraceMsg(err, "FeedbackUpload: upload failed")
	}

	psiphon.NoticeInfo("FeedbackUpload: upload succeeded")

	return nil
}