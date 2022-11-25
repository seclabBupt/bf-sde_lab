#### 生成conf配置文件
   找到 /p4_doc_internal-master/ba-102-labs/02-simple_l3_acl/solution/p4src 文件夹下的 try_all.sh 文件，对里面的代码进行修改
   ```
   #!/bin/bash
   
   # 在源文件的路径上做修改，将其改为绝对路径
   /root/bf-sde-9.3.1/p4_doc_internal-master/tools/p4_build.sh -DNO_VARBIT --with-suffix=.no_varbit simple_l3_acl.p4
   /root/bf-sde-9.3.1/p4_doc_internal-master/tools/p4_build.sh simple_l3_acl.p4
   
   ```
   
   然后执行该文件 ./try_all.sh ,随后可以在 /bf-sde-9.3.1/install/share/p4/targets/tofino 文件夹下观察到生成了 simple_l3_acl.conf 文件，此时可以进行后面的操作

#### Shell 1 此窗口用于监听交换机
   ```
   cd /root/bf-sde-9.3.1
   . ./set_sde.bash
   ./run_tofino_model.sh -p simple_l3_acl
   ```

#### Shell 2 此窗口最终进入bf_shell
   ```
   cd /root/bf-sde-9.3.1
   . ./set_sde.bash
   ./run_switchd.sh -p simple_l3_acl
   ```
   
#### Shell 3 
   ```
   cd /root/bf-sde-9.3.1
   . ./set_sde.bash
   ./run_bfshell.sh -b /p4_doc_internal-master/ba-102-labs/02-simple_l3_acl/solution/bfrt_python/setup.py
   
   # 运行ptf-tests
   ./run_p4_tests.sh -p simple_l3_acl -t ~/p4_doc_internal-master/ba-102-labs/02-simple_l3_acl/solution/ptf-tests
   ```
   
   
