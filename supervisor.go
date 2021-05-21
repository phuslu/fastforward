package main

import (
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type workerCmd struct {
	cmd *exec.Cmd
	err error
}

var workerChan = make(chan workerCmd, 1)

func IsSupervisorProcess() bool {
	return os.Getenv("is_supervisor_process") == "1"
}

func StartWorkerProcess(delay time.Duration, executable string, arguments []string, workDir string, environ []string) {
	var ac workerCmd

	ac.cmd = exec.Command(executable, arguments...) //nolint:gosec
	ac.cmd.Stdout = os.Stdout
	ac.cmd.Stderr = os.Stderr
	ac.cmd.Env = append([]string{}, os.Environ()...)
	ac.cmd.Dir = workDir
	ac.cmd.Env = []string{"is_supervisor_process=0"}

	for _, s := range os.Environ() {
		if !strings.HasPrefix(s, "is_supervisor_process=") {
			ac.cmd.Env = append(ac.cmd.Env, s)
		}
	}
	if len(environ) != 0 {
		ac.cmd.Env = append(ac.cmd.Env, environ...)
	}

	if delay != 0 {
		time.Sleep(delay)
	}

	ac.err = ac.cmd.Start()
	if ac.err != nil {
		time.Sleep(time.Second) // delay 1s to avoid storm
	} else {
		ac.err = ac.cmd.Wait()
	}

	workerChan <- ac
}

func StartWorkerSupervisor() {
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGTERM)
	signal.Notify(sigchan, syscall.SIGINT)
	signal.Notify(sigchan, syscall.SIGHUP)

	for {
		select {
		case cmd := <-workerChan:
			if cmd.err != nil {
				go StartWorkerProcess(time.Second, cmd.cmd.Args[0], cmd.cmd.Args[1:], cmd.cmd.Dir, cmd.cmd.Env)
			}
		case sig := <-sigchan:
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				os.Exit(0)
			case syscall.SIGHUP:
				go StartWorkerProcess(0, os.Args[0], os.Args[1:], "/", nil)
			}
		}
	}
}
