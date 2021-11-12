#!/bin/bash

cd ~
git clone https://gitee.com/openeuler/kunpengsecl.git
mv kunpengsecl/ kpsecl-1.0/
tar -zcvf kpsecl-1.0.tar.gz kpsecl-1.0/
mv kpsecl-1.0/ kunpengsecl/
rpmdev-setuptree
mv kpsecl-1.0.tar.gz rpmbuild/SOURCES/
cd rpmbuild/SPECS/
cat>kunpengsecl.spec<<EOF
%define debug_package %{nil}

Name:     kpsecl
Version:  1.0
Release:  1%{?dist}
Summary:  The "kpsecl" rpm package script from WL
Summary(zh_CN):  WL "kpsecl" 程序
License:  Mulan PSL v2
URL:      https://gitee.com/openeuler/kunpengsecl
Source0:  %{name}-%{version}.tar.gz

BuildRequires:   gettext make openssl-devel
Requires:        info
Requires(preun): info

%description
This is a test program.

%package       rac
Summary:       the rac package.

%description   rac
This is a rac rpm package.

%package       ras
Summary:       the ras package.

%description   ras
This is a ras rpm package.

%prep
%autosetup -n %{name}-%{version} -p1

%build
make build

%install
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}%{_bindir}/
cp -r %{_builddir}/%{name}-%{version}/attestation/rac/pkg/* %{buildroot}%{_bindir}
rm -rf %{buildroot}%{_bindir}/ractools
cp -r %{_builddir}/%{name}-%{version}/attestation/ras/pkg/ras %{buildroot}%{_bindir}


# %check
# make check

%post
# /sbin/install-info %{_infodir}/%{name}.info %{_infodir}/dir || :

%preun
# if [ $1 = 0 ] ; then
# /sbin/install-info --delete %{_infodir}/%{name}.info %{_infodir}/dir || :
# fi

%files
%defattr(-,root,root)
%doc     README.md README.en.md
%license LICENSE

%files   rac
%{_bindir}/raagent
%{_bindir}/rahub
%{_bindir}/tbprovisioner

%files   ras
%{_bindir}/ras


%clean
rm -rf %{buildroot}


%changelog
* Thu Nov 11 2021 aaron-liwang <3214053332@qq.com> - 1.0-1
- Update to 1.0

EOF

rpmbuild -ba kunpengsecl.spec
mv ~/rpmbuild ~/kunpengsecl
