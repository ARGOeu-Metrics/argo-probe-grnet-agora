# sitelib
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%define dir /usr/libexec/argo/probes/grnet-agora

Name: argo-probe-grnet-agora
Summary: Agora related probes
Version: 0.4
Release: 1%{?dist}
License: AGPLv3
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Group: Network/Monitoring
BuildArch: noarch
Requires: python-requests, python-argparse

%description
This package includes probes for Agora. 
Currently it supports the following components:
 - Agora health check

%prep
%setup -q 

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
%{__python} setup.py install --skip-build --root %{buildroot} --record=INSTALLED_FILES
install -d -m 755 %{buildroot}/%{dir}
install -d -m 755 %{buildroot}/%{python_sitelib}/grnet_agora

%clean
rm -rf %{buildroot}

%files -f INSTALLED_FILES
%defattr(-,root,root,-)
%{python_sitelib}/argo-probe-grnet-agora
%{dir}


%changelog
* Mon Sep 24 2018 Antonios Angelakis <angelakis@grnet.gr> 0.1
- Initial version of the package
