package detect

import (
	"context"
	"errors"
	"os"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// DetectFiles runs detections against a chanel of scan targets
//
// Deprecated: Use sources.Files and Detector.DetectSource instead
func (d *Detector) DetectFiles(scanTargets <-chan sources.ScanTarget) ([]report.Finding, error) {
	ctx := context.Background()

	for scanTarget := range scanTargets {
		dispatchErr := d.Scheduler.Go(ctx, scanTarget.Path, scanTarget.Size, func(taskCtx context.Context) error {
			logger := logging.With().Str("path", scanTarget.Path).Logger()
			logger.Trace().Msg("scanning path")

			f, err := os.Open(scanTarget.Path)
			if err != nil {
				if os.IsPermission(err) {
					err = errors.New("permission denied")
				}

				logger.Warn().Err(err).Msg("skipping file")
				return nil
			}
			defer func() {
				_ = f.Close()
			}()

			info, err := f.Stat()
			if err != nil {
				logger.Error().Err(err).Msg("skipping file: could not get info")
				return nil
			}

			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug().Msg("skipping empty file")
				return nil
			}

			// Too large; nothing to do here.
			if d.MaxTargetMegaBytes > 0 {
				rawLength := info.Size() / 1_000_000
				if rawLength > int64(d.MaxTargetMegaBytes) {
					logger.Warn().Msgf(
						"skipping file: too large max_size=%dMB, size=%dMB",
						d.MaxTargetMegaBytes, rawLength,
					)
					return nil
				}
			}

			// Convert this to a file source
			file := sources.File{
				Content:         f,
				Path:            scanTarget.Path,
				Symlink:         scanTarget.Symlink,
				Config:          &d.Config,
				MaxArchiveDepth: d.MaxArchiveDepth,
			}

			return file.Fragments(taskCtx, func(fragCtx context.Context, fragment sources.Fragment, err error) error {
				if err != nil {
					logging.Error().Err(err)
					return nil
				}

				for _, finding := range d.DetectContext(fragCtx, Fragment(fragment)) {
					d.AddFinding(finding)
				}
				return nil
			})
		})

		if errors.Is(dispatchErr, sources.ErrMemoryBudget) {
			// Already logged by the scheduler; drain the remaining targets so
			// each is logged too.
			continue
		}
		if dispatchErr != nil {
			return d.findings, dispatchErr
		}
	}

	d.Scheduler.Wait()
	return d.findings, nil
}
