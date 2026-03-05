#!/bin/bash

socat STDIO EXEC:"/usr/bin/bash",setsid,ctty,openpty,stderr
