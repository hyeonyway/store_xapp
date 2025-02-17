#!/bin/bash
sudo kubectl logs $(sudo kubectl get pods -o name -n ricxapp | grep "e2node-terminator") -n ricxapp -f
