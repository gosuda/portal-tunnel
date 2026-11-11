package localtls

import (
	"errors"
	"os"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func lockCertificate(path string) (*os.File, error) {
	file, err := utils.TryLockFile(path)
	if errors.Is(err, utils.ErrFileLocked) {
		return nil, errAutomaticCertificateBusy
	}
	return file, err
}
