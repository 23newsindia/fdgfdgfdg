<?php
// includes/class-settings.php

if (!defined('ABSPATH')) {
    exit;
}

class SecuritySettings {
    private $bot_settings;
    
    public function __construct() {
        // Load bot settings component
        require_once plugin_dir_path(__FILE__) . 'class-bot-settings.php';
        $this->bot_settings = new BotSettings();
    }
    
    public function add_admin_menu() {
        add_menu_page(
            'Security Settings',
            'Security Settings',
            'manage_options',
            'security-settings',
            array($this, 'render_settings_page'),
            'dashicons-shield',
            30
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        if (isset($_POST['save_settings'])) {
            $this->save_settings();
            echo '<div class="notice notice-success"><p>Settings saved successfully!</p></div>';
        }

        // Get all options
        $options = array(
            'enable_xss' => get_option('security_enable_xss', true),
            'enable_waf' => get_option('security_enable_waf', true),
            'enable_seo_features' => get_option('security_enable_seo_features', true),
            'enable_cookie_banner' => get_option('security_enable_cookie_banner', false),
            'cookie_notice_text' => get_option('security_cookie_notice_text', 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.'),
            'excluded_paths' => get_option('security_excluded_paths', ''),
            'blocked_patterns' => get_option('security_blocked_patterns', ''),
            'excluded_php_paths' => get_option('security_excluded_php_paths', ''),
            'remove_feeds' => get_option('security_remove_feeds', false),
            'remove_oembed' => get_option('security_remove_oembed', false),
            'remove_pingback' => get_option('security_remove_pingback', false),
            'remove_wp_json' => get_option('security_remove_wp_json', false),
            'remove_rsd' => get_option('security_remove_rsd', false),
            'remove_wp_generator' => get_option('security_remove_wp_generator', false),
            'remove_query_strings' => get_option('security_remove_query_strings', false),
            'waf_request_limit' => get_option('security_waf_request_limit', 500),
            'waf_blacklist_threshold' => get_option('security_waf_blacklist_threshold', 10),
            'enable_strict_csp' => get_option('security_enable_strict_csp', false),
            'allow_adsense' => get_option('security_allow_adsense', false),
            'allow_youtube' => get_option('security_allow_youtube', false),
            'allow_twitter' => get_option('security_allow_twitter', false),
            'allowed_script_domains' => get_option('security_allowed_script_domains', ''),
            'allowed_style_domains' => get_option('security_allowed_style_domains', ''),
            'allowed_image_domains' => get_option('security_allowed_image_domains', ''),
            'allowed_frame_domains' => get_option('security_allowed_frame_domains', ''),
            'enable_bot_blocking' => get_option('security_enable_bot_blocking', true)
        );
        ?>
        <div class="wrap">
            <h1><span class="dashicons dashicons-shield-alt"></span> Enhanced Security Settings</h1>
            
            <div class="notice notice-info">
                <p><strong>📍 Looking for Live Traffic Tracking?</strong> Go to the <strong>"Bot Protection"</strong> tab below to find Live Traffic Tracking controls!</p>
            </div>
            
            <!-- Tab Navigation -->
            <h2 class="nav-tab-wrapper">
                <a href="#general-tab" class="nav-tab nav-tab-active" onclick="switchTab(event, 'general-tab')">General Security</a>
                <a href="#bot-protection-tab" class="nav-tab" onclick="switchTab(event, 'bot-protection-tab')">Bot Protection</a>
                <a href="#csp-tab" class="nav-tab" onclick="switchTab(event, 'csp-tab')">Content Security Policy</a>
                <a href="#cleanup-tab" class="nav-tab" onclick="switchTab(event, 'cleanup-tab')">WordPress Cleanup</a>
            </h2>
            
            <form method="post" action="">
                <?php wp_nonce_field('security_settings_nonce', 'security_nonce'); ?>
                
                <!-- General Security Tab -->
                <div id="general-tab" class="tab-content">
                    <table class="form-table">
                        <tr>
                            <th>Core Security Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_xss" value="1" <?php checked($options['enable_xss']); ?>>
                                    Enable XSS Protection & Security Headers
                                </label>
                                <p class="description">Enables Content Security Policy, XSS protection, and other security headers</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="enable_waf" value="1" <?php checked($options['enable_waf']); ?>>
                                    Enable Web Application Firewall (WAF)
                                </label>
                                <p class="description">Protects against SQL injection, XSS, and other common attacks</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="enable_seo_features" value="1" <?php checked($options['enable_seo_features']); ?>>
                                    Enable SEO & Anti-Spam Features
                                </label>
                                <p class="description">Includes 410 responses for spam URLs and SEO optimization</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="enable_bot_blocking" value="1" <?php checked($options['enable_bot_blocking']); ?>>
                                    Enable Bot Blocking (Pattern-based System)
                                </label>
                                <p class="description">Alternative bot blocking system using pattern detection and rate limiting</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>WAF Settings</th>
                            <td>
                                <label>
                                    Request Limit per Minute:
                                    <input type="number" name="waf_request_limit" value="<?php echo esc_attr($options['waf_request_limit']); ?>" min="10" max="5000">
                                </label>
                                <p class="description">Maximum requests allowed per IP per minute (increased to 500 for better compatibility)</p>
                                
                                <br><br>
                                <label>
                                    Blacklist Threshold (violations/24h):
                                    <input type="number" name="waf_blacklist_threshold" value="<?php echo esc_attr($options['waf_blacklist_threshold']); ?>" min="1" max="100">
                                </label>
                                <p class="description">Number of violations before IP is blacklisted (increased to 10 for better compatibility)</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Cookie Consent</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_cookie_banner" value="1" <?php checked($options['enable_cookie_banner']); ?>>
                                    Enable Cookie Consent Banner
                                </label>
                                <p class="description">Shows a cookie consent banner to comply with GDPR/privacy laws</p>
                                
                                <br><br>
                                <label>
                                    Cookie Notice Text:
                                    <textarea name="cookie_notice_text" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['cookie_notice_text']); ?></textarea>
                                </label>
                                <p class="description">Customize the cookie consent notice text</p>
                            </td>
                        </tr>
                        
                        
                        <tr>
    <th>410 Redirect Settings</th>
    <td>
        <label>
            <input type="checkbox" name="enable_410_redirect" value="1" <?php checked(get_option('security_enable_410_redirect')); ?>>
            Enable 410 Redirect for 404 Pages
        </label>
        <p class="description">If enabled, all 404 pages will return a 410 status and redirect to the Security 410 page, unless excluded.</p>
        
        <br><br>
        <label>
            Excluded URLs (one per line):
            <textarea name="security_410_excluded_urls" rows="5" cols="50" class="large-text"><?php echo esc_textarea(get_option('security_410_excluded_urls', '')); ?></textarea>
        </label>
        <p class="description">Example: /example-page/, /category/sample/</p>
    </td>
</tr>

                        
                        
                        
                        
                        
                        <tr>
                            <th>Path Exclusions</th>
                            <td>
                                <label>
                                    Excluded Paths (one per line):
                                    <textarea name="excluded_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_paths']); ?></textarea>
                                </label>
                                <p class="description">Paths to exclude from security checks (e.g., wp-admin/, wp-login.php)</p>
                                
                                <br><br>
                                <label>
                                    PHP Access Exclusions (one per line):
                                    <textarea name="excluded_php_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_php_paths']); ?></textarea>
                                </label>
                                <p class="description">Paths to allow direct PHP access (e.g., wp-admin/, wp-login.php)</p>
                                
                                <br><br>
                                <label>
                                    Blocked Patterns (one per line):
                                    <textarea name="blocked_patterns" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['blocked_patterns']); ?></textarea>
                                </label>
                                <p class="description">URL patterns to block (e.g., %3C, %3E, malicious strings)</p>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <!-- Bot Protection Tab -->
                <?php $this->bot_settings->render_bot_settings(); ?>
                
                <!-- Content Security Policy Tab -->
                <div id="csp-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Content Security Policy</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_strict_csp" value="1" <?php checked($options['enable_strict_csp']); ?>>
                                    Enable Strict Content Security Policy
                                </label>
                                <p class="description">More restrictive CSP rules (may break some plugins/themes)</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Third-Party Services</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="allow_adsense" value="1" <?php checked($options['allow_adsense']); ?>>
                                    Allow Google AdSense
                                </label><br>
                                <label>
                                    <input type="checkbox" name="allow_youtube" value="1" <?php checked($options['allow_youtube']); ?>>
                                    Allow YouTube Embeds
                                </label><br>
                                <label>
                                    <input type="checkbox" name="allow_twitter" value="1" <?php checked($options['allow_twitter']); ?>>
                                    Allow Twitter Embeds
                                </label>
                                <p class="description">Allow specific third-party services in CSP</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Custom Domains</th>
                            <td>
                                <label>
                                    Allowed Script Domains (one per line):
                                    <textarea name="allowed_script_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_script_domains']); ?></textarea>
                                </label>
                                <p class="description">Additional domains allowed to load scripts</p>
                                
                                <br><br>
                                <label>
                                    Allowed Style Domains (one per line):
                                    <textarea name="allowed_style_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_style_domains']); ?></textarea>
                                </label>
                                <p class="description">Additional domains allowed to load stylesheets</p>
                                
                                <br><br>
                                <label>
                                    Allowed Image Domains (one per line):
                                    <textarea name="allowed_image_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_image_domains']); ?></textarea>
                                </label>
                                <p class="description">Additional domains allowed to load images</p>
                                
                                <br><br>
                                <label>
                                    Allowed Frame Domains (one per line):
                                    <textarea name="allowed_frame_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_frame_domains']); ?></textarea>
                                </label>
                                <p class="description">Additional domains allowed to be embedded in frames</p>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <!-- WordPress Cleanup Tab -->
                <div id="cleanup-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr style="background: #fff3cd; border: 2px solid #ffc107;">
                            <th style="color: #856404;"><strong>🗑️ Remove WordPress Features</strong></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="remove_feeds" value="1" <?php checked($options['remove_feeds']); ?>>
                                    <strong>Remove ALL RSS/Atom Feeds</strong>
                                </label>
                                <p class="description" style="color: #856404;"><strong>Completely removes all RSS and Atom feeds from your site</strong></p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="remove_oembed" value="1" <?php checked($options['remove_oembed']); ?>>
                                    Remove oEmbed Links
                                </label>
                                <p class="description">Removes oEmbed discovery links and functionality</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="remove_pingback" value="1" <?php checked($options['remove_pingback']); ?>>
                                    Remove Pingback & Disable XMLRPC
                                </label>
                                <p class="description">Disables pingbacks and XMLRPC functionality</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="remove_wp_json" value="1" <?php checked($options['remove_wp_json']); ?>>
                                    Remove WP REST API Links (wp-json)
                                </label>
                                <p class="description">Removes REST API discovery links from head</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="remove_rsd" value="1" <?php checked($options['remove_rsd']); ?>>
                                    Remove RSD Link
                                </label>
                                <p class="description">Removes Really Simple Discovery link</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="remove_wp_generator" value="1" <?php checked($options['remove_wp_generator']); ?>>
                                    Remove WordPress Generator Meta Tag
                                </label>
                                <p class="description">Hides WordPress version from HTML head</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="remove_query_strings" value="1" <?php checked($options['remove_query_strings']); ?>>
                                    Remove Excessive Query Strings
                                    
                                    <br><br>
<label>
    Allowed Query Strings (comma-separated):
    <input type="text" name="allowed_query_strings" value="<?php echo esc_attr(get_option('security_allowed_query_strings', '')); ?>" class="regular-text">
</label>
<p class="description">Example: filter,search,page — leave empty to block all.</p>

                                    
                                    
                                    
                                    
                                    
                                </label>
                                <p class="description">Removes non-essential query parameters from URLs (keeps WooCommerce filters)</p>
                                
                                <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 4px; margin-top: 15px;">
                                    <strong>🛡️ Feed Removal Benefits:</strong>
                                    <ul style="margin: 5px 0 0 20px;">
                                        <li>✅ Prevents content scraping via RSS feeds</li>
                                        <li>✅ Reduces server load from feed requests</li>
                                        <li>✅ Eliminates duplicate content issues</li>
                                        <li>✅ Improves SEO by focusing on main content</li>
                                        <li>✅ Blocks automated content theft</li>
                                    </ul>
                                </div>
                                
                                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin-top: 10px;">
                                    <strong>⚠️ Warning:</strong> Removing feeds will break RSS subscriptions and feed readers. Only enable if you don't use feeds.
                                </div>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <p class="submit">
                    <input type="submit" name="save_settings" class="button button-primary" value="Save All Settings">
                </p>
            </form>
        </div>
        
        <style>
        .nav-tab-wrapper {
            border-bottom: 1px solid #ccc;
            margin: 20px 0;
        }
        .nav-tab {
            background: #f1f1f1;
            border: 1px solid #ccc;
            border-bottom: none;
            color: #555;
            text-decoration: none;
            padding: 8px 12px;
            margin-right: 5px;
            display: inline-block;
        }
        .nav-tab-active {
            background: #fff;
            color: #000;
            border-bottom: 1px solid #fff;
            margin-bottom: -1px;
        }
        .tab-content {
            background: #fff;
            border: 1px solid #ccc;
            border-top: none;
            padding: 20px;
            margin-bottom: 20px;
        }
        </style>
        
        <script>
        function switchTab(evt, tabName) {
            var i, tabcontent, tablinks;
            
            // Hide all tab content
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            
            // Remove active class from all tabs
            tablinks = document.getElementsByClassName("nav-tab");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].classList.remove("nav-tab-active");
            }
            
            // Show the selected tab and mark as active
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.classList.add("nav-tab-active");
            
            evt.preventDefault();
        }
        </script>
        <?php
    }

    public function register_settings() {
        // Register all security settings
        $settings = array(
            'security_enable_xss',
            'security_enable_waf',
            'security_enable_seo_features',
            'security_enable_cookie_banner',
            'security_cookie_notice_text',
            'security_excluded_paths',
            'security_blocked_patterns',
            'security_excluded_php_paths',
            'security_remove_feeds',
            'security_remove_oembed',
            'security_remove_pingback',
            'security_remove_wp_json',
            'security_allowed_query_strings',
            'security_remove_rsd',
            'security_remove_wp_generator',
            'security_remove_query_strings',
            'security_waf_request_limit',
            'security_waf_blacklist_threshold',
            'security_enable_strict_csp',
            'security_allow_adsense',
            'security_allow_youtube',
            'security_allow_twitter',
            'security_allowed_script_domains',
            'security_allowed_style_domains',
            'security_allowed_image_domains',
            'security_allowed_frame_domains',
            'security_enable_bot_blocking'
        );
        
        foreach ($settings as $setting) {
            register_setting('security_settings', $setting);
        }
        
        // Register bot settings
        $this->bot_settings->register_bot_settings();
    }

    private function save_settings() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Verify nonce
        if (!isset($_POST['security_nonce']) || !wp_verify_nonce($_POST['security_nonce'], 'security_settings_nonce')) {
            wp_die('Security check failed');
        }

        // Save general settings
        update_option('security_enable_xss', isset($_POST['enable_xss']));
        update_option('security_enable_waf', isset($_POST['enable_waf']));
        update_option('security_enable_seo_features', isset($_POST['enable_seo_features']));
        update_option('security_enable_cookie_banner', isset($_POST['enable_cookie_banner']));
        update_option('security_cookie_notice_text', sanitize_textarea_field($_POST['cookie_notice_text']));
        update_option('security_excluded_paths', sanitize_textarea_field($_POST['excluded_paths']));
        update_option('security_blocked_patterns', wp_unslash($_POST['blocked_patterns']));

        update_option('security_excluded_php_paths', sanitize_textarea_field($_POST['excluded_php_paths']));
        update_option('security_waf_request_limit', intval($_POST['waf_request_limit']));
        update_option('security_waf_blacklist_threshold', intval($_POST['waf_blacklist_threshold']));
        update_option('security_enable_bot_blocking', isset($_POST['enable_bot_blocking']));
        
        // Save WordPress cleanup settings
        update_option('security_remove_feeds', isset($_POST['remove_feeds']));
        update_option('security_remove_oembed', isset($_POST['remove_oembed']));
        update_option('security_remove_pingback', isset($_POST['remove_pingback']));
        update_option('security_remove_wp_json', isset($_POST['remove_wp_json']));
        update_option('security_remove_rsd', isset($_POST['remove_rsd']));
        update_option('security_remove_wp_generator', isset($_POST['remove_wp_generator']));
        update_option('security_remove_query_strings', isset($_POST['remove_query_strings']));
        update_option('security_allowed_query_strings', sanitize_text_field($_POST['allowed_query_strings']));

        
        // Save CSP settings
        update_option('security_enable_strict_csp', isset($_POST['enable_strict_csp']));
        update_option('security_allow_adsense', isset($_POST['allow_adsense']));
        update_option('security_allow_youtube', isset($_POST['allow_youtube']));
        update_option('security_allow_twitter', isset($_POST['allow_twitter']));
        update_option('security_allowed_script_domains', sanitize_textarea_field($_POST['allowed_script_domains']));
        update_option('security_allowed_style_domains', sanitize_textarea_field($_POST['allowed_style_domains']));
        update_option('security_allowed_image_domains', sanitize_textarea_field($_POST['allowed_image_domains']));
        update_option('security_allowed_frame_domains', sanitize_textarea_field($_POST['allowed_frame_domains']));
        
        
        update_option('security_enable_410_redirect', isset($_POST['enable_410_redirect']));
        update_option('security_410_excluded_urls', sanitize_textarea_field($_POST['security_410_excluded_urls']));

        
        // Save bot settings
        $this->bot_settings->save_bot_settings();
    }
}
