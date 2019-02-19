Summary: TrustedASMPolicies for the Application Services Gateway
Name: TrustedASMPolicies
Version: 1.0.3
Release: 0002
BuildArch: noarch
Group: Development/Libraries
License: Apache-2.0
Packager: F5 DevCentral Community <j.gruber@f5.com>

%description
iControl LX extension to export ASM policies from trusted TMOS devices and upload them to other trusted devices

%define APP_DIR /var/config/rest/iapps/%{name}

%prep
cp -r %{main}/src %{_builddir}/%{name}-%{version}

%build
npm prune --production

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{APP_DIR}
cp -r $RPM_BUILD_DIR/%{name}-%{version}/* $RPM_BUILD_ROOT/%{APP_DIR}

%clean
rm -rf ${buildroot}

%files
%defattr(-,root,root)
%{APP_DIR}

%changelog
* Fri Jan 11 2019 iApp Dev <iappsdev@f5.com>
- auto-generated this spec file
