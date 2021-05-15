package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

type workerCmd struct {
	cmd *exec.Cmd
	err error
}

var workerChan = make(chan workerCmd, 1)

func IsWorkerProcess() bool {
	return os.Getenv("is_worker_process") == "1"
}

func StartWorkerProcess(delay time.Duration, executable string, arguments []string, workDir string, environ []string) {
	var ac workerCmd

	ac.cmd = exec.Command(executable, arguments...) //nolint:gosec
	ac.cmd.Stdout = os.Stdout
	ac.cmd.Stderr = os.Stderr
	ac.cmd.Env = append([]string{"is_worker_process=1"}, os.Environ()...)
	ac.cmd.Dir = workDir

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
