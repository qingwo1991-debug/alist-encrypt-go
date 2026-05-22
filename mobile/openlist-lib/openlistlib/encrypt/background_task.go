package encrypt

import log "github.com/sirupsen/logrus"

func recoverBackgroundTask(name string) {
	if r := recover(); r != nil {
		log.Errorf("[encrypt][bg] %s panic: %v", name, r)
	}
}
