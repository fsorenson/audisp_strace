Name:           audisp-strace
Version:        1.0.0
Release:        1%{?dist}
Summary:        Linux audit event consumer and strace-like trace formatter

License:        MIT
URL:            https://github.com/fsorenson/audisp_strace
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  make
BuildRequires:  python3-devel
BuildRequires:  python3-audit

Requires:       python3 >= 3.8
Requires:       python3-audit
Requires:       audit

%description
audisp-strace translates raw Linux audit events (from stdin, live auditd
plugin dispatch, or offline audit logs) into clear, human-readable system call
traces modeled after strace, enriched with full process ancestry trees,
comprehensive process credentials, and security contexts.

%prep
%autosetup

%build
# Pure Python script; no compilation required.

%install
make install DESTDIR=%{buildroot} PREFIX=%{_prefix} BINDIR=%{_bindir} SYSCONFDIR=%{_sysconfdir} PLUGINDIR=%{_sysconfdir}/audit/plugins.d

%check
make test

%post
if [ -d /run/systemd/system ]; then
    systemctl try-reload-or-restart auditd.service >/dev/null 2>&1 || :
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/audisp-strace
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/audit/plugins.d/audisp-strace.conf

%changelog
* Sat Oct 31 2026 Frank Sorenson <sorenson@redhat.com> - 1.0.0-1
- Initial v1.0.0 release
