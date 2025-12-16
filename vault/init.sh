#!/bin/sh

pkill vault

vault server -config=/vault/config/config.hcl