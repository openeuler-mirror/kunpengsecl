%global name kunpengsecl
%global version 2.0.0
%undefine _missing_build_ids_terminate_build

Name:            %{name}
Version:         %{version}
Release:         1%{?dist}
Summary:         A remote attestation security software components running on Kunpeng processors.
Summary(zh_CN):  一款运行于鲲鹏处理器上的远程证明安全软件组件
License:         MulanPSL-2.0
URL:             https://gitee.com/openeuler/kunpengsecl
Source0:         %{name}-v%{version}.tar.gz
Source1:         vendor.tar.gz
BuildRequires:   gettext make golang
BuildRequires:   protobuf-compiler openssl-devel

%ifarch     aarch64
BuildRequires:   itrustee_sdk-devel
Requires:        itrustee_sdk
%endif

Requires:        openssl itrustee_sdk
Packager:        leezhenxiang, WangLi, Wucaijun, gwei3

%description
This is %{name} project, including rac, ras, rahub, qcaserver, attester and tas packages.

%package       rac
Summary:       the rac package.

%description   rac
This is the rac rpm package, which is used to install the client of the program.

%package       ras
Summary:       the ras package.

%description   ras
This is the ras rpm package, which is used to install the server of the program.

%package       rahub
Summary:       the rahub package.

%description   rahub
This is the rahub rpm package, which is used to cascade clients.

%package       qcaserver
Summary:       the qcaserver package.

%description   qcaserver
This is the qcaserver rpm package, which is used to invoke libqca.

%package       attester
Summary:       the attester package.

%description   attester
This is the attester rpm package, which is used to verify ta reports.

%package       tas
Summary:       the tas package.

%description   tas
This is the tas rpm package, which is used to sign ak cert.

%prep
%setup -q -c -a 1

%build
make build

%install
make install DESTDIR=%{buildroot}

# %check
# make check

%post

%preun

%files   rac
%{_bindir}/raagent
#%{_bindir}/tbprovisioner
%{_sysconfdir}/attestation/rac/config.yaml
%{_sysconfdir}/attestation/default_test/ascii_runtime_measurements*
%{_sysconfdir}/attestation/default_test/binary_bios_measurements*
%{_datadir}/attestation/rac/containerintegritytool.sh
%{_datadir}/attestation/rac/pcieintegritytool.sh
%{_datadir}/attestation/rac/hostintegritytool.sh
%{_datadir}/attestation/rac/prepare-racconf-env.sh
%{_docdir}/attestation/rac/README.md
%{_docdir}/attestation/rac/README.en.md
%{_docdir}/attestation/rac/LICENSE

%files   ras
%{_bindir}/ras
%{_sysconfdir}/attestation/ras/config.yaml
%{_datadir}/attestation/ras/prepare-database-env.sh
%{_datadir}/attestation/ras/clear-database.sh
%{_datadir}/attestation/ras/createTable.sql
%{_datadir}/attestation/ras/clearTable.sql
%{_datadir}/attestation/ras/dropTable.sql
%{_datadir}/attestation/ras/prepare-rasconf-env.sh
%{_docdir}/attestation/ras/README.md
%{_docdir}/attestation/ras/README.en.md
%{_docdir}/attestation/ras/LICENSE

%files   rahub
%{_bindir}/rahub
%{_sysconfdir}/attestation/rahub/config.yaml
%{_datadir}/attestation/rahub/prepare-hubconf-env.sh
%{_docdir}/attestation/rahub/README.md
%{_docdir}/attestation/rahub/README.en.md
%{_docdir}/attestation/rahub/LICENSE

%files   qcaserver
%{_bindir}/qcaserver
%{_sysconfdir}/attestation/qcaserver/config.yaml
%{_datadir}/attestation/qcaserver/prepare-qcaconf-env.sh
%{_docdir}/attestation/qcaserver/README.md
%{_docdir}/attestation/qcaserver/README.en.md
%{_docdir}/attestation/qcaserver/LICENSE
%{_datadir}/attestation/qcaserver/libqca.so
%{_datadir}/attestation/qcaserver/libteec.so

%files   attester
%{_bindir}/attester
%{_sysconfdir}/attestation/attester/config.yaml
%{_datadir}/attestation/attester/prepare-attesterconf-env.sh
%{_docdir}/attestation/attester/README.md
%{_docdir}/attestation/attester/README.en.md
%{_docdir}/attestation/attester/LICENSE
%{_datadir}/attestation/attester/libteeverifier.so

%files   tas
%{_bindir}/tas
%{_sysconfdir}/attestation/tas/config.yaml
%{_datadir}/attestation/tas/prepare-tasconf-env.sh
%{_docdir}/attestation/tas/README.md
%{_docdir}/attestation/tas/README.en.md
%{_docdir}/attestation/tas/LICENSE

%clean
rm -rf %{_builddir}
rm -rf %{buildroot}

%changelog
* Thu Mar 23 2023 leezhenxiang <1172294056@qq.com> - 2.0.0-1
-   update to 2.0.0
-   add qcaserver, attester, and tas packages
-   add BuildRequires itrustee_sdk-devel and Requires itrustee_sdk in aarch64
-   modify makefile to adapt to different architectures
* Thu Sep 15 2022 gwei3 <11015100@qq.com> - 1.1.2-1
-   update to 1.1.2
-   add slice length checks to avoid buffer overflow while extracting and verifying
-   update integration test data to meet restapi parameter check requirement
-   modify raagent/main.go file, change log to logger, os.Exit returns different values based on diff errors
-   close RAS restapi server in signal handler
-   Add parameter format checking for pcr/bios/ima in POST {id}/newbasevalue API
-   Fix bugs in v1.1.1
    bug 1: hostintegritytool.sh can only add the 2nd part of ima policy into /etc/ima/ima-policy.
    bug 2: running hostintegritytool.sh multiple times will add duplicated linux cmdlines in /etc/default/grub.
    bug 3: rahub config path was assigned wrong values, which is caused by copy/paste
-   fix the issue that Makefile not sync vendor
-   modify readme file
* Fri Sep 02 2022 gwei3 <11015100@qq.com> - 1.1.1-1
-   update to 1.1.1
-   reuse makefile to do install
-   remove the empty kunpengsecl binary rpm
* Tue Aug 09 2022 wangli <3214053332@qq.com> - 1.1.0-3
-   process vendor directory
* Wed Aug 03 2022 fushanqing <fushanqing@kylinos.cn> - 1.1.0-2
-   Unified license name specification
* Sun Jul 24 2022 wangli <3214053332@qq.com> - 1.1.0-1
-   add some test files
-   prepare corresponding script for ras\rac\rahub to deploy config file respectively
-   update part of file paths
-   update to 1.1.0
* Fri Jan 21 2022 wangli <3214053332@qq.com> - 1.0.0-5
-   install some test files to support the running of program.
* Mon Dec 27 2021 gwei3 <11015100@qq.com> - 1.0.0-4
-   update the source tar to remove intermediate files.
* Wed Dec 08 2021 wangli <3214053332@qq.com> - 1.0.0-3
-   add the rahub package.
-   reorganize the directory structure of all packages.
-   add BuildRequires protobuf-compiler and Requires openssl.
* Fri Nov 12 2021 wucaijun <wucaijun2001@163.com> - 1.0.0-2
-   create the rpmbuild directory.
-   modify the kunpengsecl.spec and buildrpm.sh files.
-   add root Makefile to build/clean rpm package.
* Thu Nov 11 2021 wangli <3214053332@qq.com> - 1.0.0-1
-   update to 1.0.0
