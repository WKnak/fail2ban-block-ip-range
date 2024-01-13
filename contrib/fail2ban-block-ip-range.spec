#
# Fedora/Enterprise Linux spec file for "fail2ban-block-ip-range"
#

# manual build
# rpmbuild -bb --undefine=_disable_source_fetch contrib/fail2ban-block-ip-range.spec

# manual build with gitcommit
# rpmbuild -bb --undefine=_disable_source_fetch -D "gitcommit <hash>" contrib/fail2ban-block-ip-range.spec

Name:      fail2ban-block-ip-range
BuildArch: noarch
Version:   1.0.0
Release:   1
Summary:   fail2ban block ip/network range
License:   Unknown
URL:       https://github.com/WKnak/fail2ban-block-ip-range
Group:     Unspecified

Requires:  fail2ban
%{?systemd_requires}

BuildRequires: systemd-rpm-macros


%if 0%{?gitcommit:1}
Source0:   https://github.com/pbiering/fail2ban-block-ip-range/archive/%{gitcommit}/fail2ban-block-ip-range-%{gitcommit}.tar.gz
%else
# Temporary until upstream has accepted
Source0:   https://github.com/pbiering/fail2ban-block-ip-range/archive/%{version}/fail2ban-block-ip-range-%{version}.tar.gz
%endif


%description
fail2ban block ip/network range
Scan /var/log/fail2ban.log and aggregate single banned IPs into banned networks
Currently only supporting IPv4


%prep
%if 0%{?gitcommit:1}
%setup -q -n fail2ban-block-ip-range-%{gitcommit}
%else
%setup -q -n fail2ban-block-ip-range-%{version}
%endif


%build
# Nothing


%install
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_bindir}
install -m 0644 fail2ban-block-ip-range.timer   %{buildroot}%{_unitdir}
install -m 0644 fail2ban-block-ip-range.service %{buildroot}%{_unitdir}
install -m 0755 fail2ban-block-ip-range.py      %{buildroot}%{_bindir}

cd -


%post
%systemd_post %{name}.service
%systemd_post %{name}.timer


%posttrans
if ! systemctl -q is-active fail2ban-block-ip-range.timer; then
	cat <<END

Consider activation of fail2ban-block-ip-range.timer using
	systemctl enable --now fail2ban-block-ip-range.timer

END
fi


%preun
%systemd_preun %{name}.service
%systemd_preun %{name}.timer


%postun
%systemd_postun %{name}.service
%systemd_postun %{name}.timer


%files
%{_unitdir}/*.service
%{_unitdir}/*.timer
%attr(755,root,root) %{_bindir}/*.py


%changelog
* Mon Jan 01 2024 Peter Bieringer <pb@bieringer.de> - 1.0.0-1
- Initial release 1.0.0
