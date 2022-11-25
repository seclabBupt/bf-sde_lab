#!/bin/bash

# 用于生成配置文件 前面为加入绝对路径
/root/bf-sde-9.3.1/p4_doc_internal-master/tools/p4_build.sh -DNO_VARBIT --with-suffix=.no_varbit simple_l3_acl.p4
/root/bf-sde-9.3.1/p4_doc_internal-master/tools/p4_build.sh simple_l3_acl.p4
