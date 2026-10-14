// SPDX-License-Identifier: Apache-2.0
package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"zoli.dev/intel-feed/internal/model"
)

func (w *Worker) RuntimeEvidenceOne(ctx context.Context) (bool, error) {
	j, err := w.Store.Claim(ctx, "runtime-evidence", time.Minute)
	if err != nil || j == nil {
		return false, err
	}
	var result RuntimeResult
	if err = json.Unmarshal(j.Payload, &result); err != nil {
		return true, w.Store.Finish(ctx, *j, nil, err)
	}
	id := candidateID(result.Artifact)
	record, err := w.Store.Get(ctx, id)
	if err != nil {
		return true, w.Store.Finish(ctx, *j, nil, err)
	}
	changed := false
	for _, input := range result.Evidence {
		if input.RuleID != "ZOLI-RUNTIME-001" || input.RuleVersion != "1.0.0" || input.ArtifactSHA256 != result.Artifact.SHA256 {
			return true, w.Store.Finish(ctx, *j, nil, errors.New("unsupported runtime evidence"))
		}
		observations := []string{}
		for _, o := range input.Observations {
			switch o {
			case "Access to synthetic credential path observed", "Network connection attempted with external egress disabled", "Process execution observed":
				observations = append(observations, o)
			}
		}
		if len(observations) == 0 {
			continue
		}
		ev := model.Evidence{RuleID: input.RuleID, RuleVersion: input.RuleVersion, ArtifactSHA256: input.ArtifactSHA256, Explanation: "Runtime observations in isolated gVisor environment; operator review required", Observations: observations, Reproduce: "zoli-intel sandbox --descriptor <artifact.json> --config <recorded runner config>", Limitations: []string{"External runtime egress was disabled", "Execution may have been partial; no clean verdict is issued", "Private trace sha256: " + result.TraceSHA256}}
		exists := false
		for _, old := range record.Evidence {
			if old.RuleID == ev.RuleID {
				exists = true
				break
			}
		}
		if !exists {
			record.Evidence = append(record.Evidence, ev)
			changed = true
		}
	}
	if changed {
		record.Sources[0].Revision = model.Hash([]byte(record.Sources[0].Revision + result.TraceSHA256))
		if err = w.Store.Ingest(ctx, record, false); err != nil {
			return true, w.Store.Finish(ctx, *j, nil, err)
		}
	}
	return true, w.Store.Finish(ctx, *j, map[string]string{"status": "awaiting_review"}, nil)
}
