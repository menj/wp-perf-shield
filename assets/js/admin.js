(function($) {
	'use strict';

	var cfg = window.WPS_ADMIN || {};
	var nonce = cfg.nonce || '';
	var ajaxUrl = cfg.ajaxUrl || window.ajaxurl;

	function statusStyles(ok) {
		return {
			background: ok ? '#eaf3de' : '#fcebeb',
			border: '1px solid ' + (ok ? '#639922' : '#e24b4a'),
			color: ok ? '#3b6d11' : '#a32d2d'
		};
	}

	function msg(text, ok) {
		$('#wps-msg').css(statusStyles(ok)).html(text).show();
	}

	function remMsg(text, ok) {
		$('#wps-rem-msg').css(statusStyles(ok)).html(text).show();
	}

	function settingsMsg(text, ok) {
		$('#wps-settings-msg').css(statusStyles(ok)).text(text).show();
	}

	function esc(text) {
		return $('<div>').text(text || '').html();
	}

	function shortHardeningMessage(text, payload) {
		var message = String(text || '').replace(/\s+/g, ' ').trim();

		if (payload && payload.actionName === 'wps_regenerate_salts') {
			return 'Salts regenerated. Log in again if prompted.';
		}
		if (payload && payload.actionName === 'wps_invalidate_sessions') {
			return 'Sessions invalidated.';
		}
		if (message.indexOf('Applied:') === 0) {
			return 'Applied';
		}
		if (message.indexOf('Enabled:') === 0) {
			return 'Enabled';
		}
		if (message.indexOf('Disabled:') === 0 || message.indexOf('Removed:') === 0) {
			return 'Removed';
		}
		if (payload && payload.enable === '0') {
			return 'Removed';
		}
		if (message.length > 32) {
			return message.slice(0, 29) + '...';
		}

		return message || 'Done';
	}

	function hardeningConfirmMessage(action, payload, label) {
		if (action === 'wps_regenerate_salts') {
			return 'Regenerate all WordPress auth salts?\nThis invalidates every current login session, including yours. You may need to log in again.';
		}
		if (action === 'wps_invalidate_sessions') {
			return 'Invalidate all WordPress user sessions?\nEvery user will need to log in again.';
		}
		if (action === 'wps_wpconfig_constant') {
			return 'Apply this wp-config.php hardening constant?\nA backup will be created before writing.';
		}
		if (action === 'wps_htaccess_rule') {
			return (String((payload || {}).enable || '1') === '0' ? 'Remove' : 'Apply') + ' this .htaccess hardening rule?';
		}
		return String(label || 'Run this action') + '?';
	}

	function post(data, done) {
		return $.post(ajaxUrl, $.extend({ nonce: nonce }, data), done);
	}

	$('#wps-scan-btn').on('click', function() {
		var $b = $(this).prop('disabled', true).text('Scanning...');

		post({ action: 'wps_run_scan' }, function(r) {
			$b.prop('disabled', false).text('Run scan now');
			if (r.success) {
				msg(
					r.data.length
						? r.data.length + ' issue(s) found - <a href="?page=wp-perf-shield&tab=overview">reload to see details</a>.'
						: 'Clean - no issues found.',
					!r.data.length
				);
			}
		}).fail(function() {
			$b.prop('disabled', false).text('Run scan now');
			msg('Request failed - check server error log.', false);
		});
	});

	$('#wps-rebaseline-btn').on('click', function() {
		if (!window.confirm('Reset the wp-config.php integrity baseline?\nThe current file hash will be stored as the new clean state.\nOnly do this after an intentional edit.')) {
			return;
		}

		post({ action: 'wps_rebaseline_wpconfig' }, function(r) {
			if (r.success) {
				settingsMsg('Baseline reset. New hash stored. The finding will clear on next scan.', true);
			} else {
				settingsMsg('Error: ' + (r.data ? r.data.error : 'unknown'), false);
			}
		});
	});

	$('#wps-rebaseline-dropins-btn').on('click', function() {
		if (!window.confirm('Reset the drop-in integrity baseline?\nThe current set of wp-content drop-ins will become the new clean reference.\nOnly do this after an intentional change, and never while a drop-in finding is unexplained.')) {
			return;
		}

		post({ action: 'wps_rebaseline_dropins' }, function(r) {
			if (r.success) {
				settingsMsg('Drop-in baseline reset (' + (r.data ? r.data.count : 0) + ' tracked). Findings clear on next scan.', true);
			} else {
				settingsMsg('Error: ' + (r.data ? r.data.error : 'unknown'), false);
			}
		});
	});

	$('#wps-rebaseline-php-inventory-btn').on('click', function() {
		if (!window.confirm('Reset the PHP-inventory baseline?\nThe PHP files currently in uploads and mu-plugins become the new clean reference.\nOnly do this after a confirmed cleanup, and never while a drift finding is unexplained.')) {
			return;
		}

		post({ action: 'wps_rebaseline_php_inventory' }, function(r) {
			if (r.success) {
				settingsMsg('PHP-inventory baseline reset (' + (r.data ? r.data.count : 0) + ' files). Drift findings clear on next scan.', true);
			} else {
				settingsMsg('Error: ' + (r.data ? r.data.error : 'unknown'), false);
			}
		});
	});

	// 1.3.73: Logs tab. All log content is rendered via jQuery .text() (escapes
	// like textContent) because access logs carry attacker-controlled strings.
	function wpsLogShow(title) {
		$('#wps-log-output-title').text(title);
		$('#wps-log-output').empty();
		$('#wps-log-output-wrap').show();
	}
	function wpsLogLine(text, matched) {
		var $line = $('<div>');
		if (matched) {
			$line.css({ background: '#5c1a1a', color: '#ffd9d9', padding: '1px 5px', borderRadius: '2px', margin: '1px 0' });
			$line.text('[' + matched + ']  ' + text);
		} else {
			$line.text(text);
		}
		$('#wps-log-output').append($line);
	}

	$('#wps-log-scanall-btn').on('click', function() {
		var $b = $(this).prop('disabled', true);
		$('#wps-log-scan-status').text('Scanning all readable logs...');
		post({ action: 'wps_log_inspect', mode: 'scanall' }, function(r) {
			$b.prop('disabled', false);
			if (!r.success) { $('#wps-log-scan-status').text('Error: ' + (r.data ? r.data.error : 'unknown')); return; }
			var results = (r.data && r.data.results) ? r.data.results : [];
			var total = 0;
			wpsLogShow('Campaign IOC scan across all readable logs');
			if (!results.length) {
				wpsLogLine('No campaign indicators found in any readable log.', '');
			} else {
				results.forEach(function(res) {
					$('#wps-log-output').append($('<div>').css({ color: '#7fd1ff', marginTop: '8px', fontWeight: '700' }).text('== ' + res.path + ' (' + res.hits.length + ' hit(s)) =='));
					res.hits.forEach(function(h) { wpsLogLine(h.line, h.matched); total++; });
				});
			}
			$('#wps-log-scan-status').text(total + ' indicator line(s) across ' + results.length + ' log(s).');
		});
	});

	$('.wps-log-tail-btn').on('click', function() {
		var path = $(this).data('path');
		wpsLogShow('Tail: ' + path);
		post({ action: 'wps_log_inspect', mode: 'tail', path: path }, function(r) {
			if (!r.success) { wpsLogLine('Error: ' + (r.data ? r.data.error : 'unknown'), ''); return; }
			var lines = (r.data && r.data.lines) ? r.data.lines : [];
			if (!lines.length) { wpsLogLine('(empty or unreadable)', ''); return; }
			lines.forEach(function(l) { wpsLogLine(l, ''); });
		});
	});

	$('.wps-log-iocscan-btn').on('click', function() {
		var path = $(this).data('path');
		wpsLogShow('IOC scan: ' + path);
		post({ action: 'wps_log_inspect', mode: 'iocscan', path: path }, function(r) {
			if (!r.success) { wpsLogLine('Error: ' + (r.data ? r.data.error : 'unknown'), ''); return; }
			var hits = (r.data && r.data.hits) ? r.data.hits : [];
			if (!hits.length) { wpsLogLine('No campaign indicators in this log.', ''); return; }
			hits.forEach(function(h) { wpsLogLine(h.line, h.matched); });
		});
	});

	$('#wps-log-output-close').on('click', function() { $('#wps-log-output-wrap').hide(); });

	$('#wps-log-loginscan-btn').on('click', function() {
		var $b = $(this).prop('disabled', true);
		$('#wps-log-scan-status').text('Scanning access logs for automated logins...');
		post({ action: 'wps_log_inspect', mode: 'loginscanall' }, function(r) {
			$b.prop('disabled', false);
			if (!r.success) { $('#wps-log-scan-status').text('Error: ' + (r.data ? r.data.error : 'unknown')); return; }
			var results = (r.data && r.data.results) ? r.data.results : [];
			var total = 0;
			wpsLogShow('Automated-login signature (direct POST to wp-login.php with no page load, or xmlrpc.php auth)');
			if (!results.length) {
				wpsLogLine('No direct-POST or xmlrpc login pattern found in readable access logs. (If your access log is not PHP-readable, check it in your hosting panel.)', '');
			} else {
				results.forEach(function(res) {
					$('#wps-log-output').append($('<div>').css({ color: '#7fd1ff', marginTop: '8px', fontWeight: '700' }).text('== ' + res.path + ' =='));
					res.suspect.forEach(function(s) {
						var label = s.ip + '  (' + s.posts + ' direct login POST(s)' + (s.xmlrpc ? ', ' + s.xmlrpc + ' xmlrpc hit(s)' : '') + ')';
						wpsLogLine(label, 'auto-login');
						total++;
					});
				});
			}
			$('#wps-log-scan-status').text(total + ' suspect IP(s) across ' + results.length + ' log(s).');
		});
	});

	$('#wps-clear-ip-blocks-btn').on('click', function() {
		if (!window.confirm('Clear all hostile IP auto-blocks?\nOnly do this if you have moved blocking to your WAF/hosting firewall or need to correct a false positive.')) {
			return;
		}

		post({ action: 'wps_clear_ip_blocks' }, function(r) {
			if (r.success) {
				settingsMsg('Hostile IP block list cleared. Reloading...', true);
				window.setTimeout(function() { window.location.reload(); }, 600);
			} else {
				settingsMsg('Error: ' + (r.data ? r.data.error : 'unknown'), false);
			}
		});
	});

	$('#wps-clear-btn-log').on('click', function() {
		if (!window.confirm('Permanently clear all logged events?')) {
			return;
		}
		post({ action: 'wps_clear_log' }, function() {
			window.location.reload();
		});
	});

	$('#wps-del-exfil-btn').on('click', function() {
		if (!window.confirm('Find and permanently delete the credential exfil file?\nContents will be logged first.')) {
			return;
		}

		var $b = $(this).prop('disabled', true).text('Deleting...');
		post({ action: 'wps_delete_exfil' }, function(r) {
			$b.prop('disabled', false).text('Delete exfil file');
			if (r.success) {
				var d = r.data;
				var detail = esc(d.message || '');

				if (d.files && d.files.length) {
					detail += '<br><br><strong>Deleted files:</strong><br>';
					d.files.forEach(function(f) {
						detail += '<code style="font-size:11px">' + esc(f.file) + '</code> - '
							+ (parseInt(f.lines, 10) || 0) + ' line(s)<br>';
					});
				}

				remMsg(detail, d.deleted && d.deleted.length > 0);
			} else {
				remMsg('Error: ' + esc(r.data ? r.data.error : 'unknown'), false);
			}
		}).fail(function() {
			$b.prop('disabled', false).text('Delete exfil file');
			remMsg('Request failed.', false);
		});
	});

	$('#wps-clean-login-btn').on('click', function() {
		if (!window.confirm('Remove the credential harvester injection from wp-login.php?')) {
			return;
		}

		var $b = $(this).prop('disabled', true).text('Cleaning...');
		post({ action: 'wps_clean_login' }, function(r) {
			$b.prop('disabled', false).text('Clean wp-login.php');
			remMsg(r.success ? esc(r.data.message) : 'Error: ' + esc(r.data ? r.data.error : 'unknown'), !!r.success);
		}).fail(function() {
			$b.prop('disabled', false).text('Clean wp-login.php');
			remMsg('Request failed.', false);
		});
	});

	$('#wps-clean-funcs-btn').on('click', function() {
		if (!window.confirm('Remove the credential harvester injection from the active theme functions.php?')) {
			return;
		}

		var $b = $(this).prop('disabled', true).text('Cleaning...');
		post({ action: 'wps_clean_functions' }, function(r) {
			$b.prop('disabled', false).text('Clean functions.php');
			remMsg(r.success ? esc(r.data.message) : 'Error: ' + esc(r.data ? r.data.error : 'unknown'), !!r.success);
		}).fail(function() {
			$b.prop('disabled', false).text('Clean functions.php');
			remMsg('Request failed.', false);
		});
	});

	$('#wps-clean-cron-btn').on('click', function() {
		if (!window.confirm('Download a clean wp-cron.php from official WordPress source mirrors and replace the tampered version?')) {
			return;
		}

		var $b = $(this).prop('disabled', true).text('Replacing...');
		post({ action: 'wps_clean_cron' }, function(r) {
			$b.prop('disabled', false).text('Replace wp-cron.php');
			remMsg(r.success ? esc(r.data.message) : 'Error: ' + esc(r.data ? r.data.error : 'unknown'), !!r.success);
		}).fail(function() {
			$b.prop('disabled', false).text('Replace wp-cron.php');
			remMsg('Request failed.', false);
		});
	});

	$('#wps-clean-wpconfig-btn').on('click', function() {
		if (!window.confirm('Clean known malware patterns from wp-config.php?\nA backup will be created before writing. Review the backup and cleaned file after this completes.')) {
			return;
		}

		var $b = $(this).prop('disabled', true).text('Cleaning...');
		post({ action: 'wps_clean_wpconfig' }, function(r) {
			$b.prop('disabled', false).text('Clean wp-config.php');
			if (r.success) {
				var d = r.data || {};
				var detail = esc(d.message || 'wp-config.php clean completed.');

				if (d.removed && d.removed.length) {
					detail += '<br>Removed: ';
					detail += d.removed.map(function(item) {
						return '<code>' + esc(item.label || item.id || 'pattern') + '</code>';
					}).join(', ');
				}

				remMsg(detail, true);
			} else {
				remMsg('Error: ' + esc(r.data ? r.data.error : 'unknown'), false);
			}
		}).fail(function() {
			$b.prop('disabled', false).text('Clean wp-config.php');
			remMsg('Request failed.', false);
		});
	});

	$('#wps-del-db-btn').on('click', function() {
		if (!window.confirm('Scan the options table and delete all known malicious options?\nThis cannot be undone.')) {
			return;
		}

		var $b = $(this).prop('disabled', true).text('Scanning DB...');
		post({ action: 'wps_delete_db_options' }, function(r) {
			$b.prop('disabled', false).text('Delete malicious DB options');
			if (r.success) {
				var d = r.data;
				var detail = esc(d.message || '');

				if (d.deleted && d.deleted.length) {
					detail += '<br>Deleted: ' + d.deleted.map(function(opt) {
						return '<code>' + esc(opt) + '</code>';
					}).join(', ');
				}

				remMsg(detail, true);
			} else {
				remMsg('Error: ' + esc(r.data ? r.data.error : 'unknown'), false);
			}
		}).fail(function() {
			$b.prop('disabled', false).text('Delete malicious DB options');
			remMsg('Request failed.', false);
		});
	});

	$('#wps-forensics-btn').on('click', function() {
		var $b = $(this).prop('disabled', true).text('Analysing...');

		$('#wps-forensics-status').show().text('Running forensic checks - this may take 10-20 seconds...');
		$('#wps-forensics-results').css('opacity', '0.5');

		post({ action: 'wps_run_forensics' }, function(r) {
			$b.prop('disabled', false).text('Run forensics');
			$('#wps-forensics-status').hide();
			$('#wps-forensics-results').css('opacity', '1');

			if (r.success) {
				window.location.reload();
			} else {
				$('#wps-forensics-status')
					.show()
					.css(statusStyles(false))
					.text('Forensics failed - check PHP error log.');
			}
		}).fail(function() {
			$b.prop('disabled', false).text('Run forensics');
			$('#wps-forensics-status').show().text('Request timed out. Try again.');
		});
	});

	$('.wps-app').on('click', '.wps-hardening-action', function() {
		var $b = $(this);
		var label = $b.data('wpsLabel') || $b.text();
		var action = $b.data('wpsAction');
		var payload = $b.data('wpsPayload') || {};
		var $target = $('#' + $b.attr('id') + '-msg');

		if ($b.data('wpsConfirm') && !window.confirm(hardeningConfirmMessage(action, payload, label))) {
			return;
		}

		payload.actionName = action;
		$b.prop('disabled', true).text('Applying...');

		post($.extend({ action: action }, payload), function(r) {
			$b.prop('disabled', false).text(label);

			if (r.success) {
				$target
					.removeClass('is-error')
					.addClass('is-visible is-ok')
					.text(shortHardeningMessage(r.data ? r.data.message : '', payload));

				if (action === 'wps_htaccess_rule' || action === 'wps_wpconfig_constant') {
					$b.hide();
					window.setTimeout(function() {
						window.location.reload();
					}, 700);
				} else if (action === 'wps_regenerate_salts' || action === 'wps_invalidate_sessions') {
					$b.hide();
				}
			} else {
				$target
					.removeClass('is-ok')
					.addClass('is-visible is-error')
					.text(r.data ? r.data.error : 'Error');
			}
		}).fail(function() {
			$b.prop('disabled', false).text(label);
			$target.removeClass('is-ok').addClass('is-visible is-error').text('Request failed.');
		});
	});

	// 1.3.95: delegated handlers (no inline onclick; CSP-friendly).
	$(document).on('click', '[data-wps-action]', function() {
		var $b = $(this);
		var data;
		try { data = JSON.parse($b.attr('data-wps-data') || '{}'); } catch (e) { data = {}; }
		window.wpsForensicAct(this, $b.attr('data-wps-action'), data, $b.attr('data-wps-confirm') || '');
	});
	$(document).on('click', '[data-wps-copy]', function() {
		var t = this.previousElementSibling, b = this;
		if (!t) { return; }
		navigator.clipboard.writeText(t.textContent);
		b.textContent = 'Copied!';
		setTimeout(function() { b.textContent = 'Copy'; }, 1500);
	});

	window.wpsForensicAct = function(btn, action, data, confirmMsg) {
		if (confirmMsg && !window.confirm(confirmMsg)) {
			return;
		}

		var $b = $(btn).prop('disabled', true).css('opacity', '0.6');
		var payload = $.extend({ action: action }, data || {});

		post(payload, function(r) {
			$b.prop('disabled', false).css('opacity', '1');

			var $row = $b.closest('tr,div.wps-finding,div.wps-finding-card');
			if (r.success) {
				// 1.3.85: the bulk base64 delete clears many rows at once; reload
				// so the card and counts reflect the spliced report rather than
				// trying to grey each affected row individually.
				if (action === 'wps_delete_all_unknown_b64' || action === 'wps_quarantine_restore' || action === 'wps_quarantine_purge' || action === 'wps_quarantine_empty') {
					window.alert((r.data && r.data.message) ? r.data.message : 'Done');
					window.location.reload();
					return;
				}
				$row.css({ background: '#eaf3de', opacity: '0.6' });
				// 1.3.62: jQuery element constructor with `text:` field auto-
				// escapes server-supplied success messages instead of inserting
				// them as raw HTML via string concatenation. Several remediation
				// handlers compose r.data.message from user-influenced data
				// (attachment titles, option keys, file basenames) so the
				// previous `'<span...>' + r.data.message + '</span>'` pattern
				// was a defence-in-depth concern even though the practical
				// XSS reach was narrow (admin clicking remediate on attacker-
				// influenced strings).
				$b.replaceWith($('<span>', {
					'class': 'wps-inline-success',
					text: (r.data && r.data.message) ? r.data.message : 'Done'
				}));
			} else {
				window.alert('Error: ' + (r.data ? r.data.error : 'Unknown error'));
				$b.prop('disabled', false).css('opacity', '1');
			}
		}).fail(function() {
			window.alert('Request failed - check server error log.');
			$b.prop('disabled', false).css('opacity', '1');
		});
	};

	// Phase 5: redacted diagnostics export. The handler returns a JSON bundle
	// inside r.data; we wrap it as a Blob and trigger a download. Nothing is
	// sent to a third party  the request stays inside the WP admin AJAX URL.
	$('#wps-export-diag-btn').on('click', function() {
		var $b = $(this).prop('disabled', true).text('Generating...');
		var $msg = $('#wps-export-diag-msg');

		function showMsg(text, ok) {
			$msg.css(statusStyles(ok)).text(text).show();
		}

		post({ action: 'wps_export_diagnostics' }, function(r) {
			$b.prop('disabled', false).text('💾 Download support bundle (JSON)');
			if (!r.success) {
				showMsg('Error: ' + (r.data ? r.data.error : 'unknown'), false);
				return;
			}
			try {
				var bundle = r.data;
				var blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
				var url = URL.createObjectURL(blob);
				var ts = (bundle.generated_at || '').replace(/[^0-9A-Za-z-]/g, '-');
				var version = bundle.plugin_version || '';
				var fname = 'wp-perf-shield-diagnostics-' + version + '-' + ts + '.json';
				var a = document.createElement('a');
				a.href = url;
				a.download = fname;
				document.body.appendChild(a);
				a.click();
				document.body.removeChild(a);
				setTimeout(function() { URL.revokeObjectURL(url); }, 1500);
				showMsg('Downloaded ' + fname, true);
			} catch (e) {
				showMsg('Could not generate download: ' + (e && e.message ? e.message : 'unknown'), false);
			}
		}).fail(function() {
			$b.prop('disabled', false).text('💾 Download support bundle (JSON)');
			showMsg('Request failed.', false);
		});
	});
	// 1.3.76: Content-Security-Policy controls (Hardening tab).
	function wpsCspMsg(t, ok) { $('#wps-csp-msg').css('color', ok ? '#1a7f37' : '#a32d2d').text(t); }

	$('#wps-csp-default-btn').on('click', function() {
		var mode = $('input[name="wps-csp-mode"]:checked').val() || 'off';
		post({ action: 'wps_csp', op: 'save', mode: mode, policy: '' }, function(r) {
			if (r.success && r.data && r.data.policy) {
				$('#wps-csp-policy').val(r.data.policy);
				wpsCspMsg('Default policy restored and saved.', true);
			} else {
				wpsCspMsg('Error: ' + (r.data ? r.data.error : 'unknown'), false);
			}
		});
	});

	$('#wps-csp-save-btn').on('click', function() {
		var mode = $('input[name="wps-csp-mode"]:checked').val() || 'off';
		var policy = $('#wps-csp-policy').val() || '';
		if (mode === 'enforce' && !window.confirm('Enforce mode BLOCKS anything the policy disallows and can break your site if the policy is not tuned.\n\nHave you reviewed the violation reports in Report-only mode and added your legitimate hosts to connect-src?\n\nClick OK only if you are sure.')) {
			return;
		}
		var $b = $(this).prop('disabled', true);
		post({ action: 'wps_csp', op: 'save', mode: mode, policy: policy }, function(r) {
			$b.prop('disabled', false);
			if (r.success) {
				wpsCspMsg('Saved (mode: ' + (r.data ? r.data.mode : mode) + ').', true);
			} else {
				wpsCspMsg('Error: ' + (r.data ? r.data.error : 'unknown'), false);
			}
		});
	});

	$('#wps-csp-clear-btn').on('click', function() {
		if (!window.confirm('Clear all stored CSP violation reports?')) { return; }
		post({ action: 'wps_csp', op: 'clear' }, function(r) {
			if (r.success) { wpsCspMsg('Reports cleared. Reload the page to refresh the table.', true); }
			else { wpsCspMsg('Error: ' + (r.data ? r.data.error : 'unknown'), false); }
		});
	});


	// 1.3.95: self-block admin notice - clear hostile IP blocks. The notice can
	// render on any admin page; the blocker enqueues this file alongside it.
	$(document).on('click', '#wps-self-block-clear-btn', function() {
		var btn = this, status = document.getElementById('wps-self-block-status');
		btn.disabled = true; btn.textContent = 'Clearing...';
		if (status) { status.textContent = ''; }
		$.post(ajaxUrl, { action: 'wps_clear_ip_blocks', nonce: nonce }, function(j) {
			if (j && j.success) {
				if (status) { status.className = 'wps-good-t'; status.textContent = 'Cleared. Reloading...'; }
				setTimeout(function() { window.location.reload(); }, 700);
			} else {
				btn.disabled = false; btn.textContent = 'Clear hostile IP blocks now';
				if (status) { status.className = 'wps-bad-t'; status.textContent = 'Failed - check permissions.'; }
			}
		});
	});

})(jQuery);
