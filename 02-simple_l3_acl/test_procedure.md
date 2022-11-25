#### 生成conf配置文件
   找到 /p4_doc_internal-master/ba-102-labs/02-simple_l3_acl/solution/p4src 文件夹下的 try_all.sh 文件，对里面的代码进行修改
   ```
   #!/bin/bash
   
   # 在源文件的路径上做修改，将其改为绝对路径
   /root/bf-sde-9.3.1/p4_doc_internal-master/tools/p4_build.sh -DNO_VARBIT --with-suffix=.no_varbit simple_l3_acl.p4
   /root/bf-sde-9.3.1/p4_doc_internal-master/tools/p4_build.sh simple_l3_acl.p4
   
   ```
   
   然后执行该文件 ./try_all.sh ,随后可以在 /bf-sde-9.3.1/install/share/p4/targets/tofino 文件夹下观察到生成了 simple_l3_acl.conf 文件，此时可以进行后面的操作
