package sweetcookie

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

var execCommandContext = exec.CommandContext

func execCapture(ctx context.Context, name string, args []string) (stdout string, stderr string, err error) {
	cmd := execCommandContext(ctx, name, args...)
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if runErr != nil {
		return stdout, stderr, fmt.Errorf("%s: %w", name, runErr)
	}
	return stdout, stderr, nil
}
