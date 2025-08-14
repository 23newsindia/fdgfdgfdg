<?php
// includes/class-bot-settings.php

if (!defined('ABSPATH')) {
    exit;
}

class BotSettings {
    public function add_bot_settings_section($settings) {
        // Add bot protection settings to the main settings class
        $settings->add_settings_section('bot-protection', 'Bot Protection', array($this, 'render_bot_settings'));
        return $settings;
    }
    
    public function render_bot_settings() {
        $options = array(
            'enable_bot_protection' => get_option('security_enable_bot_protection', true),
            'bot_skip_logged_users' => get_option('security_bot_skip_logged_users', true),
            'bot_max_requests_per_minute' => get_option('security_bot_max_requests_per_minute', 30),
            'bot_block_threshold' => get_option('security_bot_block_threshold', 5),
            'bot_block_message' => get_option('security_bot_block_message', 'Access Denied: Automated requests not allowed.'),
            'bot_log_retention_days' => get_option('security_bot_log_retention_days', 30),
            'bot_whitelist_ips' => get_option('security_bot_whitelist_ips', ''),
            'bot_whitelist_agents' => get_option('security_bot_whitelist_agents', $this->get_default_whitelist_bots()),
            'bot_email_alerts' => get_option('security_bot_email_alerts', false),
            'bot_alert_email' => get_option('security_bot_alert_email', get_option('admin_email')),
            'bot_block_status' => get_option('security_bot_block_status', 403),
            'bot_custom_message' => get_option('security_bot_custom_message', ''),
            'protect_admin' => get_option('security_protect_admin', false),
            'protect_login' => get_option('security_protect_login', false),
            'enable_traffic_capture' => get_option('security_enable_traffic_capture', false),
            'max_traffic_entries' => get_option('security_max_traffic_entries', 1000),
            'bot_stealth_mode' => get_option('security_bot_stealth_mode', true),
            'enable_live_tracking' => get_option('security_enable_live_tracking', true),
            'track_all_visitors' => get_option('security_track_all_visitors', false),
            'show_full_urls' => get_option('security_show_full_urls', true),
            'track_ajax_requests' => get_option('security_track_ajax_requests', true)
        );
        ?>
        <div id="bot-protection-tab" class="tab-content" style="display:none;">
            <table class="form-table">
                <tr>
                    <th>Enable Bot Protection</th>
                    <td>
                        <label>
                            <input type="checkbox" name="enable_bot_protection" value="1" <?php checked($options['enable_bot_protection']); ?>>
                            Enable automatic bot detection and blocking (Blackhole System)
                        </label>
                        <p class="description">Automatically detects and blocks malicious bots and scrapers using blackhole traps and behavioral analysis</p>
                    </td>
                </tr>
                
                <tr style="background: #e8f5e8; border: 2px solid #28a745;">
                    <th style="color: #155724;"><strong>🔍 Live Traffic Tracking Controls</strong></th>
                    <td>
                        <label>
                            <input type="checkbox" name="enable_live_tracking" value="1" <?php checked($options['enable_live_tracking']); ?>>
                            <strong>Enable Live Traffic Tracking</strong>
                        </label>
                        <p class="description" style="color: #155724;"><strong>Track all website visitors and their activities in real-time</strong></p>
                        
                        <br><br>
                        <label>
                            <input type="checkbox" name="track_all_visitors" value="1" <?php checked($options['track_all_visitors']); ?>>
                            <strong>Track ALL Visitors (Including Logged-in Users)</strong>
                        </label>
                        <p class="description">When enabled, tracks all visitors including logged-in users and admins (normally excluded)</p>
                        
                        <br><br>
                        <label>
                            <input type="checkbox" name="show_full_urls" value="1" <?php checked($options['show_full_urls']); ?>>
                            <strong>Show Full URLs with Parameters</strong>
                        </label>
                        <p class="description">Display complete URLs including query parameters (e.g., /?wc-ajax=add_to_cart)</p>
                        
                        <br><br>
                        <label>
                            <input type="checkbox" name="track_ajax_requests" value="1" <?php checked($options['track_ajax_requests']); ?>>
                            <strong>Track AJAX Requests</strong>
                        </label>
                        <p class="description">Include AJAX requests like WooCommerce cart updates in tracking</p>
                        
                        <br><br>
                        <label>
                            Maximum Traffic Entries:
                            <input type="number" name="max_traffic_entries" value="<?php echo esc_attr($options['max_traffic_entries']); ?>" min="100" max="10000">
                        </label>
                        <p class="description">Maximum number of traffic entries to keep in database (older entries are automatically deleted)</p>
                        
                        <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 4px; margin-top: 10px;">
                            <strong>🛡️ Live Tracking Features:</strong>
                            <ul style="margin: 5px 0 0 20px;">
                                <li>✅ Real-time visitor monitoring</li>
                                <li>✅ Complete URL tracking with parameters</li>
                                <li>✅ AJAX request monitoring</li>
                                <li>✅ User agent and IP tracking</li>
                                <li>✅ Referrer information</li>
                                <li>✅ Timestamp tracking</li>
                                <li>✅ Hit count per visitor</li>
                            </ul>
                        </div>
                        
                        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin-top: 10px;">
                            <strong>⚠️ Performance Note:</strong> Live tracking may impact performance on high-traffic sites. Monitor database size regularly.
                        </div>
                    </td>
                </tr>
                
                <tr style="background: #d1ecf1; border: 2px solid #17a2b8;">
                    <th style="color: #0c5460;"><strong>🗑️ Traffic Data Management</strong></th>
                    <td>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; border-left: 4px solid #007cba;">
                            <h4>Clear All Traffic Data</h4>
                            <p>Remove all tracked traffic data from the database to free up space and start fresh.</p>
                            <button type="button" id="clear-all-traffic" class="button button-secondary">Clear All Traffic Data</button>
                            <span id="clear-traffic-status" style="margin-left: 10px;"></span>
                            
                            <br><br>
                            <h4>Clear Non-Blocked Traffic Only</h4>
                            <p>Remove only monitoring data, keep blocked bot records.</p>
                            <button type="button" id="clear-monitoring-traffic" class="button">Clear Monitoring Data</button>
                            <span id="clear-monitoring-status" style="margin-left: 10px;"></span>
                        </div>
                        
                        <script>
                        document.getElementById('clear-all-traffic').addEventListener('click', function() {
                            if (!confirm('Are you sure you want to clear ALL traffic data? This will remove all visitor tracking records including blocked bots.')) {
                                return;
                            }
                            
                            var button = this;
                            var status = document.getElementById('clear-traffic-status');
                            
                            button.disabled = true;
                            button.textContent = 'Clearing...';
                            status.textContent = '';
                            
                            fetch(ajaxurl, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                },
                                body: 'action=clear_all_traffic_data&nonce=' + encodeURIComponent('<?php echo wp_create_nonce('clear_all_traffic_data'); ?>')
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.success) {
                                    status.innerHTML = '<span style="color: green;">✓ All traffic data cleared successfully!</span>';
                                } else {
                                    status.innerHTML = '<span style="color: red;">✗ Error: ' + (data.data || 'Unknown error') + '</span>';
                                }
                            })
                            .catch(error => {
                                status.innerHTML = '<span style="color: red;">✗ Network error occurred</span>';
                            })
                            .finally(() => {
                                button.disabled = false;
                                button.textContent = 'Clear All Traffic Data';
                            });
                        });
                        
                        document.getElementById('clear-monitoring-traffic').addEventListener('click', function() {
                            if (!confirm('Are you sure you want to clear monitoring traffic data? This will keep blocked bot records but remove visitor tracking data.')) {
                                return;
                            }
                            
                            var button = this;
                            var status = document.getElementById('clear-monitoring-status');
                            
                            button.disabled = true;
                            button.textContent = 'Clearing...';
                            status.textContent = '';
                            
                            fetch(ajaxurl, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/x-www-form-urlencoded',
                                },
                                body: 'action=clear_traffic_logs&nonce=' + encodeURIComponent('<?php echo wp_create_nonce('clear_traffic_logs'); ?>')
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.success) {
                                    status.innerHTML = '<span style="color: green;">✓ Monitoring data cleared successfully!</span>';
                                } else {
                                    status.innerHTML = '<span style="color: red;">✗ Error: ' + (data.data || 'Unknown error') + '</span>';
                                }
                            })
                            .catch(error => {
                                status.innerHTML = '<span style="color: red;">✗ Network error occurred</span>';
                            })
                            .finally(() => {
                                button.disabled = false;
                                button.textContent = 'Clear Monitoring Data';
                            });
                        });
                        </script>
                    </td>
                </tr>
                
                <tr style="background: #d1ecf1; border: 2px solid #17a2b8;">
                    <th style="color: #0c5460;"><strong>🔍 Legacy Traffic Capture</strong></th>
                    <td>
                        <label>
                            <input type="checkbox" name="enable_traffic_capture" value="1" <?php checked($options['enable_traffic_capture']); ?>>
                            <strong>Enable Legacy Traffic Monitoring</strong>
                        </label>
                        <p class="description" style="color: #0c5460;"><strong>Legacy system - use Live Traffic Tracking above instead</strong></p>
                        
                        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin-top: 10px;">
                            <strong>💡 Recommendation:</strong> Use the new "Live Traffic Tracking" above instead of this legacy system for better performance and features.
                        </div>
                    </td>
                </tr>
                
                <tr>
                    <th>Stealth Mode</th>
                    <td>
                        <label>
                            <input type="checkbox" name="bot_stealth_mode" value="1" <?php checked($options['bot_stealth_mode']); ?>>
                            Enable stealth mode blackhole traps
                        </label>
                        <p class="description">Uses JavaScript-based hidden traps instead of HTML (recommended to avoid false malware detection)</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Protection Areas</th>
                    <td>
                        <label>
                            <input type="checkbox" name="protect_admin" value="1" <?php checked($options['protect_admin']); ?>>
                            Protect Admin Area
                        </label>
                        <p class="description">Enable bot protection for wp-admin (not recommended for most sites)</p>
                        
                        <br><br>
                        <label>
                            <input type="checkbox" name="protect_login" value="1" <?php checked($options['protect_login']); ?>>
                            Protect Login Page
                        </label>
                        <p class="description">Enable bot protection for wp-login.php</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Skip Logged-in Users</th>
                    <td>
                        <label>
                            <input type="checkbox" name="bot_skip_logged_users" value="1" <?php checked($options['bot_skip_logged_users']); ?>>
                            Skip bot detection for logged-in users
                        </label>
                        <p class="description">Recommended to avoid blocking legitimate users</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Rate Limiting</th>
                    <td>
                        <label>
                            Max requests per minute:
                            <input type="number" name="bot_max_requests_per_minute" value="<?php echo esc_attr($options['bot_max_requests_per_minute']); ?>" min="5" max="200">
                        </label>
                        <p class="description">Maximum requests allowed per IP per minute before flagging as bot</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Block Threshold</th>
                    <td>
                        <label>
                            Block after:
                            <input type="number" name="bot_block_threshold" value="<?php echo esc_attr($options['bot_block_threshold']); ?>" min="1" max="50">
                            suspicious activities
                        </label>
                        <p class="description">Number of suspicious activities before permanently blocking an IP</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Block Response</th>
                    <td>
                        <label>
                            HTTP Status Code:
                            <select name="bot_block_status">
                                <option value="403" <?php selected($options['bot_block_status'], 403); ?>>403 Forbidden</option>
                                <option value="410" <?php selected($options['bot_block_status'], 410); ?>>410 Gone</option>
                                <option value="444" <?php selected($options['bot_block_status'], 444); ?>>444 No Response</option>
                            </select>
                        </label>
                        <p class="description">HTTP status code to return to blocked bots</p>
                        
                        <br><br>
                        <label>
                            Default Block Message:
                            <textarea name="bot_block_message" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['bot_block_message']); ?></textarea>
                        </label>
                        <p class="description">Default message shown to blocked bots</p>
                        
                        <br><br>
                        <label>
                            Custom Block Page (HTML):
                            <textarea name="bot_custom_message" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['bot_custom_message']); ?></textarea>
                        </label>
                        <p class="description">Custom HTML page for blocked bots (overrides default message)</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Email Alerts</th>
                    <td>
                        <label>
                            <input type="checkbox" name="bot_email_alerts" value="1" <?php checked($options['bot_email_alerts']); ?>>
                            Send email alerts when bots are blocked
                        </label>
                        <p class="description">Get notified when malicious bots are detected and blocked</p>
                        
                        <br><br>
                        <label>
                            Alert Email Address:
                            <input type="email" name="bot_alert_email" value="<?php echo esc_attr($options['bot_alert_email']); ?>" class="regular-text">
                        </label>
                        <p class="description">Email address to receive bot alerts (defaults to admin email)</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Whitelisted IPs</th>
                    <td>
                        <textarea name="bot_whitelist_ips" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['bot_whitelist_ips']); ?></textarea>
                        <p class="description">Enter one IP address per line. Supports CIDR notation (e.g., 192.168.1.0/24)</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Whitelisted User Agents</th>
                    <td>
                        <textarea name="bot_whitelist_agents" rows="8" cols="50" class="large-text"><?php echo esc_textarea($options['bot_whitelist_agents']); ?></textarea>
                        <p class="description">Enter one user agent per line. These bots will never be blocked.</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Log Retention</th>
                    <td>
                        <label>
                            Keep logs for:
                            <input type="number" name="bot_log_retention_days" value="<?php echo esc_attr($options['bot_log_retention_days']); ?>" min="1" max="365">
                            days
                        </label>
                        <p class="description">How long to keep bot activity logs (blocked IPs are kept indefinitely)</p>
                    </td>
                </tr>
                
                <tr>
                    <th>Blackhole Trap</th>
                    <td>
                        <p class="description"><strong>Blackhole Trap Features:</strong></p>
                        <ul style="list-style-type: disc; margin-left: 20px;">
                            <li>Hidden links that only bots can see and follow</li>
                            <li>Automatic addition to robots.txt disallow list</li>
                            <li>Intelligent detection for obviously malicious requests only</li>
                            <li>Enhanced WooCommerce filter protection</li>
                            <li>Automatic IP blocking with transient caching</li>
                            <li>Your IP (103.251.55.45) is permanently whitelisted</li>
                        </ul>
                        <p class="description">The blackhole system creates invisible traps that legitimate users never see, but bots often follow, allowing for accurate bot detection.</p>
                    </td>
                </tr>
            </table>
        </div>
        <?php
    }
    
    private function get_default_whitelist_bots() {
        return 'googlebot
bingbot
slurp
duckduckbot
baiduspider
yandexbot
facebookexternalhit
meta-externalagent
twitterbot
linkedinbot
pinterestbot
applebot
ia_archiver
msnbot
ahrefsbot
semrushbot
dotbot
rogerbot
uptimerobot
pingdom
gtmetrix
pagespeed
lighthouse
chrome-lighthouse
wordpress
wp-rocket
jetpack
wordfence';
    }
    
    public function save_bot_settings() {
        // Save bot protection settings
        update_option('security_enable_bot_protection', isset($_POST['enable_bot_protection']));
        update_option('security_protect_admin', isset($_POST['protect_admin']));
        update_option('security_protect_login', isset($_POST['protect_login']));
        update_option('security_bot_skip_logged_users', isset($_POST['bot_skip_logged_users']));
        update_option('security_bot_max_requests_per_minute', intval($_POST['bot_max_requests_per_minute']));
        update_option('security_bot_block_threshold', intval($_POST['bot_block_threshold']));
        update_option('security_bot_block_status', intval($_POST['bot_block_status']));
        update_option('security_bot_block_message', sanitize_textarea_field($_POST['bot_block_message']));
        update_option('security_bot_custom_message', wp_kses_post($_POST['bot_custom_message']));
        update_option('security_bot_email_alerts', isset($_POST['bot_email_alerts']));
        update_option('security_bot_alert_email', sanitize_email($_POST['bot_alert_email']));
        update_option('security_bot_whitelist_ips', sanitize_textarea_field($_POST['bot_whitelist_ips']));
        update_option('security_bot_whitelist_agents', sanitize_textarea_field($_POST['bot_whitelist_agents']));
        update_option('security_bot_log_retention_days', intval($_POST['bot_log_retention_days']));
        update_option('security_enable_traffic_capture', isset($_POST['enable_traffic_capture']));
        update_option('security_max_traffic_entries', intval($_POST['max_traffic_entries']));
        update_option('security_bot_stealth_mode', isset($_POST['bot_stealth_mode']));
        
        // NEW: Save live tracking settings
        update_option('security_enable_live_tracking', isset($_POST['enable_live_tracking']));
        update_option('security_track_all_visitors', isset($_POST['track_all_visitors']));
        update_option('security_show_full_urls', isset($_POST['show_full_urls']));
        update_option('security_track_ajax_requests', isset($_POST['track_ajax_requests']));
    }
    
    public function register_bot_settings() {
        $settings = array(
            'security_enable_bot_protection',
            'security_protect_admin',
            'security_protect_login',
            'security_bot_skip_logged_users',
            'security_bot_max_requests_per_minute',
            'security_bot_block_threshold',
            'security_bot_block_status',
            'security_bot_block_message',
            'security_bot_custom_message',
            'security_bot_email_alerts',
            'security_bot_alert_email',
            'security_bot_whitelist_ips',
            'security_bot_whitelist_agents',
            'security_bot_log_retention_days',
            'security_enable_traffic_capture',
            'security_max_traffic_entries',
            'security_bot_stealth_mode',
            'security_enable_live_tracking',
            'security_track_all_visitors',
            'security_show_full_urls',
            'security_track_ajax_requests'
        );
        
        foreach ($settings as $setting) {
            register_setting('security_settings', $setting);
        }
    }
}