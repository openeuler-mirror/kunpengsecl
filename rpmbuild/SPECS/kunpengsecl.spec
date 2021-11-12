%global name kunpengsecl
%global version 1.1

Name:     %{name}
Version:  %{version}
Release:  1%{?dist}
Summary:  The %{name} rpm package script write by WangLi
Summary(zh_CN): %{name} rpm 打包程序由王利编写
License:  Mulan PSL v2
URL:      https://gitee.com/openeuler/kunpengsecl
Source0:   %{name}-%{version}.tar.gz
BuildRequires:   gettext make golang openssl-devel
Packager: WangLi, Wucaijun

%description
This is %{name} project, including rac and ras packages.

%package       rac
Summary:       the rac package.

%description   rac
This is the rac rpm package.

%package       ras
Summary:       the ras package.

%description   ras
This is the ras rpm package.

%prep
%setup -q -c

%build
make build

%install
rm -rf %{buildroot}/usr/local/bin/
mkdir -p %{buildroot}/usr/local/bin/
install -m 555 %{_builddir}/%{name}-%{version}/attestation/rac/pkg/raagent %{buildroot}/usr/local/bin/
install -m 555 %{_builddir}/%{name}-%{version}/attestation/rac/pkg/rahub %{buildroot}/usr/local/bin/
install -m 555 %{_builddir}/%{name}-%{version}/attestation/rac/pkg/tbprovisioner %{buildroot}/usr/local/bin/
install -m 555 %{_builddir}/%{name}-%{version}/attestation/ras/pkg/ras %{buildroot}/usr/local/bin/
rm -rf %{buildroot}/etc/%{name}/
mkdir -p %{buildroot}/etc/%{name}/
install -m 644 %{_builddir}/%{name}-%{version}/attestation/ras/config/config.yaml %{buildroot}/etc/%{name}/

# %check
# make check

%post

%preun

%files
%defattr(-,root,root,-)
%license LICENSE
%doc     README.md README.en.md
%config(noreplace) %{_sysconfdir}/%{name}/config.yaml

%files   rac
/usr/local/bin/raagent
/usr/local/bin/rahub
/usr/local/bin/tbprovisioner

%files   ras
/usr/local/bin/ras


%clean
rm -rf %{_builddir}
rm -rf %{buildroot}

%changelog
* Fri Nov 12 2021 wucaijun <wucaijun2001@163.com> - 1.1-1
-   create the rpmbuild directory.
-   modify the kunpengsecl.spec and buildrpm.sh files.
-   add root Makefile to build/clean rpm package.
* Thu Nov 11 2021 aaron-liwang <3214053332@qq.com> - 1.0-1
-   Update to 1.0
