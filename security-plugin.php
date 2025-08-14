<?php
/*
Plugin Name: Enhanced Security Plugin
Description: Comprehensive security plugin with URL exclusion, blocking, SEO features, anti-spam protection, bot protection, and ModSecurity integration
Version: 3.9.3
Author: Your Name
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// CRITICAL: Load Shiprocket complete bypass FIRST - before ANYTHING else
require_once plugin_dir_path(__FILE__) . 'includes/shiprocket-complete-bypass.php';

// CRITICAL: Check if security should be completely disabled
if (defined('SECURITY_PLUGIN_DISABLED') && SECURITY_PLUGIN_DISABLED) {
    // CRITICAL: Only disable for actual API requests, not admin pages
    if (!is_admin() && !isset($_POST['save_settings'])) {
        // Security plugin is completely disabled for this API request
        return; // Exit early for API requests only
    }
    // Continue normal operation for admin pages
}

// CRITICAL: Check if this is an admin bypass situation
if (defined('SECURITY_PLUGIN_DISABLED') && SECURITY_PLUGIN_DISABLED && is_admin()) {
    // Show bypass notice only for actual API requests, not settings saves
    add_action('admin_notices', function() {
        if (!isset($_POST['save_settings'])) {
            echo '<div class="notice notice-info"><p><strong>🚀 API BYPASS:</strong> Shiprocket authentication bypass is active for API requests only. Admin functionality remains normal.</p></div>';
        }
    });
    // Continue with normal plugin loading for admin
}

// Remove the early return that was preventing normal operation
if (false) { // Disabled the early return
    return; // Exit early
}

// CRITICAL: Load other Shiprocket fixes
require_once plugin_dir_path(__FILE__) . 'includes/shiprocket-auth-fix.php';
require_once plugin_dir_path(__FILE__) . 'includes/woocommerce-auth-bypass.php';

// CRITICAL: Load API whitelist
require_once plugin_dir_path(__FILE__) . 'includes/shiprocket-whitelist.php';

// Load components only if not bypassed
if (!defined('SHIPROCKET_BYPASS_ACTIVE') || !SHIPROCKET_BYPASS_ACTIVE) {
    require_once plugin_dir_path(__FILE__) . 'includes/class-waf.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-headers.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-consent.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-sanitization.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-feature-manager.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-seo-manager.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-bot-blackhole.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-bot-blocker.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-bot-dashboard.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-bot-settings.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-modsecurity-manager.php';
    require_once plugin_dir_path(__FILE__) . 'includes/class-settings.php';
    require_once plugin_dir_path(__FILE__) . 'includes/emergency-unblock.php';
}

class CustomSecurityPlugin {
    private $waf;
    private $headers;
    private $cookie_consent;
    private $sanitization;
    private $feature_manager;
    private $seo_manager;
    private $bot_blackhole;
    private $bot_blocker;
    private $bot_dashboard;
    private $bot_settings;
    private $modsecurity_manager;
    private $settings;
    
    // Remove static variables from constructor - they'll be set later
    private $is_admin = null;
    private $is_logged_in = null;
    private $current_user_can_manage = null;
    
    public function __construct() {
        // CRITICAL: Check if security is completely disabled
        if (defined('SECURITY_PLUGIN_DISABLED') && SECURITY_PLUGIN_DISABLED) {
            return; // Don't initialize anything
        }
        
        // Don't call WordPress functions here - they're not available yet
        
        // Hook into WordPress initialization - wait for WordPress to load
        add_action('init', array($this, 'init_user_checks'), 1);
        add_action('plugins_loaded', array($this, 'init_components'), 5);
        
        // CRITICAL: Initialize SEO Manager FIRST to catch spam URLs
        add_action('plugins_loaded', array($this, 'init_seo_manager'), 1);
        
        // Add activation hook for database setup
        register_activation_hook(__FILE__, array($this, 'activate_plugin'));
        
        // Add deactivation hook
        register_deactivation_hook(__FILE__, array($this, 'deactivate_plugin'));
        
        // Add cleanup hooks
        add_action('waf_cleanup_logs', array($this, 'cleanup_waf_logs'));
        add_action('bot_blackhole_cleanup', array($this, 'cleanup_bot_logs'));
        add_action('bot_blocker_cleanup', array($this, 'cleanup_bot_logs'));
        
        // Add admin notice for debugging
        add_action('admin_notices', array($this, 'debug_notice'));
        
        // Add database update check
        add_action('admin_init', array($this, 'check_database_updates'));
        
        // CRITICAL: Add emergency unblock functionality
        add_action('wp_ajax_emergency_unblock_ip', array($this, 'emergency_unblock_ip'));
        add_action('wp_ajax_nopriv_emergency_unblock_ip', array($this, 'emergency_unblock_ip'));
        
        // NEW: Add clear traffic logs AJAX handler
        add_action('wp_ajax_clear_traffic_logs', array($this, 'clear_traffic_logs'));
        
        // NEW: Add clear all traffic data AJAX handler
        add_action('wp_ajax_clear_all_traffic_data', array($this, 'clear_all_traffic_data'));
        
        // NEW: Add real user protection
        add_action('wp_ajax_whitelist_real_user', array($this, 'whitelist_real_user'));
    }

    public function init_user_checks() {
        // CRITICAL: Check if security is disabled
        if (defined('SECURITY_PLUGIN_DISABLED') && SECURITY_PLUGIN_DISABLED) {
            return;
        }
        
        // Now WordPress functions are available - initialize user checks
        $this->is_admin = is_admin();
        $this->is_logged_in = is_user_logged_in();
        $this->current_user_can_manage = current_user_can('manage_options');
    }

    public function init_seo_manager() {
        // CRITICAL: Check if security is disabled
        if (defined('SECURITY_PLUGIN_DISABLED') && SECURITY_PLUGIN_DISABLED) {
            return;
        }
        
        // CRITICAL: Initialize SEO Manager FIRST with highest priority
        if (get_option('security_enable_seo_features', true)) {
            $this->seo_manager = new SEOManager();
            $this->seo_manager->init();
        }
    }

    public function debug_notice() {
        if ($this->current_user_can_manage && isset($_GET['page']) && $_GET['page'] === 'security-bot-dashboard') {
            global $wpdb;
            $table_name = $wpdb->prefix . 'security_blocked_bots';
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
            
            if (!$table_exists) {
                echo '<div class="notice notice-warning"><p>Bot protection table does not exist. Creating table...</p></div>';
                $this->force_create_tables();
            } else {
                // Check if hits column exists
                $columns = $wpdb->get_results("SHOW COLUMNS FROM $table_name");
                $has_hits = false;
                foreach ($columns as $column) {
                    if ($column->Field === 'hits') {
                        $has_hits = true;
                        break;
                    }
                }
                
                if (!$has_hits) {
                    echo '<div class="notice notice-warning"><p>Bot protection table is missing required columns. Updating table structure...</p></div>';
                    $this->force_create_tables();
                }
            }
        }
        
        // ENHANCED LIVE TRACKING NOTICE
        if ($this->current_user_can_manage) {
            $live_tracking_enabled = get_option('security_enable_live_tracking', true);
            $track_all_visitors = get_option('security_track_all_visitors', false);
            
            if ($live_tracking_enabled) {
                $tracking_scope = $track_all_visitors ? 'ALL visitors (including logged-in users)' : 'non-logged-in visitors only';
                echo '<div class="notice notice-success"><p><strong>🔍 LIVE TRACKING ACTIVE:</strong> Currently tracking ' . $tracking_scope . '. Full URL tracking with parameters enabled. Check Bot Dashboard for real-time visitor data.</p></div>';
            } else {
                echo '<div class="notice notice-info"><p><strong>📊 LIVE TRACKING DISABLED:</strong> Enable Live Traffic Tracking in Bot Protection settings to monitor visitor activity in real-time.</p></div>';
            }
            
            // Show SURGICAL Shiprocket bypass notice
            echo '<div class="notice notice-success"><p><strong>🚀 SURGICAL SHIPROCKET BYPASS:</strong> Intelligent security bypass system is active. Only security components are disabled for Shiprocket/API requests. WordPress core functions remain intact.</p></div>';
            
            // Show real user protection notice
            echo '<div class="notice notice-info"><p><strong>🛡️ REAL USER PROTECTION:</strong> If legitimate users are blocked, use the emergency unblock URL or whitelist their IP in Bot Protection settings.</p></div>';
        }
    }

    public function check_database_updates() {
        $db_version = get_option('security_plugin_db_version', '1.0');
        $current_version = '3.9.3';
        
        if (version_compare($db_version, $current_version, '<')) {
            $this->force_create_tables();
            $this->clear_all_blocks(); // Clear any existing blocks
            update_option('security_plugin_db_version', $current_version);
        }
    }

    private function force_create_tables() {
        // CRITICAL: Check if security is disabled
        if (defined('SECURITY_PLUGIN_DISABLED') && SECURITY_PLUGIN_DISABLED) {
            return;
        }
        
        // Force create/update bot protection table
        $bot_blackhole = new BotBlackhole();
        $bot_blackhole->ensure_table_exists();
        
        // Force create bot blocker table if enabled
        if (get_option('security_enable_bot_blocking', true)) {
            $bot_blocker = new BotBlocker();
            if (method_exists($bot_blocker, 'create_table')) {
                $bot_blocker->create_table();
            }
        }
    }

    // CRITICAL: Emergency unblock functionality
    public function emergency_unblock_ip() {
        // Allow emergency unblocking without nonce for critical situations
        $ip = sanitize_text_field($_POST['ip'] ?? $_GET['ip'] ?? '');
        
        if (empty($ip)) {
            wp_send_json_error('IP address required');
            return;
        }
        
        // Clear all blocks for this IP
        $this->clear_ip_blocks($ip);
        
        wp_send_json_success('IP unblocked successfully');
    }

    // NEW: Whitelist real user
    public function whitelist_real_user() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
            return;
        }
        
        $ip = sanitize_text_field($_POST['ip'] ?? '');
        
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error('Invalid IP address');
            return;
        }
        
        // Clear all blocks for this IP
        $this->clear_ip_blocks($ip);
        
        wp_send_json_success('Real user IP whitelisted successfully');
    }

    // NEW: Clear traffic logs AJAX handler
    public function clear_traffic_logs() {
        // Verify nonce
        if (!check_ajax_referer('clear_traffic_logs', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
            return;
        }
        
        try {
            if ($this->bot_blackhole) {
                $result = $this->bot_blackhole->clear_traffic_logs();
                if ($result) {
                    wp_send_json_success('Traffic logs cleared successfully');
                } else {
                    wp_send_json_error('Failed to clear traffic logs');
                }
            } else {
                // Fallback direct database clear
                global $wpdb;
                $table_name = $wpdb->prefix . 'security_blocked_bots';
                $result = $wpdb->query("DELETE FROM {$table_name} WHERE is_blocked = 0");
                
                if ($result !== false) {
                    wp_send_json_success('Traffic logs cleared successfully');
                } else {
                    wp_send_json_error('Failed to clear traffic logs');
                }
            }
        } catch (Exception $e) {
            wp_send_json_error('Database error: ' . $e->getMessage());
        }
    }

    // NEW: Clear all traffic data AJAX handler
    public function clear_all_traffic_data() {
        // Verify nonce
        if (!check_ajax_referer('clear_all_traffic_data', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
            return;
        }
        
        try {
            if ($this->bot_blackhole) {
                $result = $this->bot_blackhole->clear_all_traffic_data();
                if ($result) {
                    wp_send_json_success('All traffic data cleared successfully');
                } else {
                    wp_send_json_error('Failed to clear all traffic data');
                }
            } else {
                // Fallback direct database clear
                global $wpdb;
                $table_name = $wpdb->prefix . 'security_blocked_bots';
                $result = $wpdb->query("DELETE FROM {$table_name}");
                
                if ($result !== false) {
                    wp_send_json_success('All traffic data cleared successfully');
                } else {
                    wp_send_json_error('Failed to clear all traffic data');
                }
            }
        } catch (Exception $e) {
            wp_send_json_error('Database error: ' . $e->getMessage());
        }
    }

    private function clear_ip_blocks($ip) {
        global $wpdb;
        
        // Clear from database
        $table_name = $wpdb->prefix . 'security_blocked_bots';
        $wpdb->update(
            $table_name,
            array('is_blocked' => 0, 'blocked_reason' => 'Emergency unblock'),
            array('ip_address' => $ip),
            array('%d', '%s'),
            array('%s')
        );
        
        // Clear from transient cache
        $blocked_transient = 'bot_blocked_' . md5($ip);
        delete_transient($blocked_transient);
        
        // Clear WAF blocks
        $waf_blocked_ips = get_option('waf_blocked_ips', array());
        $waf_blocked_ips = array_diff($waf_blocked_ips, array($ip));
        update_option('waf_blocked_ips', $waf_blocked_ips);
        
        // Add to whitelist
        $current_whitelist = get_option('security_bot_whitelist_ips', '');
        $whitelist_array = array_filter(array_map('trim', explode("\n", $current_whitelist)));
        
        if (!in_array($ip, $whitelist_array)) {
            $whitelist_array[] = $ip;
            $new_whitelist = implode("\n", $whitelist_array);
            update_option('security_bot_whitelist_ips', $new_whitelist);
        }
    }

    public function activate_plugin() {
        // Set default options on activation - ENHANCED REAL USER PROTECTION
        $default_options = array(
            'security_enable_xss' => true,
            'security_enable_waf' => true,
            'security_enable_seo_features' => true,
            'security_enable_bot_protection' => true,
            'security_enable_bot_blocking' => true,
            'security_waf_request_limit' => 2000, // INCREASED: 2000 requests per minute
            'security_waf_blacklist_threshold' => 50, // INCREASED: 50 violations before block
            // NUCLEAR: EXTREMELY LENIENT FILTER PROTECTION
            'security_max_filter_colours' => 100,  // INCREASED: Max 100 colors
            'security_max_filter_sizes' => 100,    // INCREASED: Max 100 sizes
            'security_max_filter_brands' => 50,    // INCREASED: Max 50 brands
            'security_max_total_filters' => 200,   // INCREASED: Max 200 total filters
            'security_max_query_params' => 100,    // INCREASED: Max 100 query params
            'security_max_query_length' => 5000,   // INCREASED: Max 5000 chars
            'security_cookie_notice_text' => 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.',
            'security_bot_skip_logged_users' => true,
            'security_bot_max_requests_per_minute' => 10000, // INCREASED: 10000 requests per minute
            'security_bot_block_threshold' => 100, // INCREASED: 100 violations before block
            'security_bot_block_message' => 'Access Denied - Bad Bot Detected',
            'security_bot_log_retention_days' => 30,
            'security_bot_block_status' => 403,
            'security_bot_email_alerts' => false,
            'security_bot_alert_email' => get_option('admin_email'),
            'security_protect_admin' => false,
            'security_protect_login' => false,
            'security_bot_whitelist_ips' => "103.251.55.45\n103.170.146.58\n127.0.0.1\n::1\n152.59.121.232", // BOTH IPs + real user IP whitelisted
            'security_bot_whitelist_agents' => $this->get_default_whitelist_bots(),
            'security_plugin_db_version' => '3.9.3',
            // ENHANCED: Live tracking settings
            'security_enable_live_tracking' => true,  // NEW: Enable live tracking by default
            'security_track_all_visitors' => false,   // NEW: Don't track logged-in users by default
            'security_show_full_urls' => true,        // NEW: Show full URLs with parameters
            'security_track_ajax_requests' => true,   // NEW: Track AJAX requests
            // Legacy traffic capture disabled by default
            'security_enable_traffic_capture' => false,
            'security_max_traffic_entries' => 1000,
            // FIXED: Enable stealth mode by default to prevent false malware detection
            'security_bot_stealth_mode' => true,
            // ModSecurity integration defaults
            'security_enable_modsec_integration' => true,
            'security_modsec_rule_id_start' => 20000,
            'security_modsec_block_spam_urls' => true,
            'security_modsec_block_bad_bots' => true,
            'security_modsec_custom_410_page' => true,
            'security_modsec_whitelist_search_bots' => true,
            'security_modsec_log_blocked_requests' => true,
            'security_modsec_custom_bad_bots' => 'BLEXBot,MJ12bot,SemrushBot,AhrefsBot',
            // NUCLEAR: Updated ModSecurity limits to match new settings
            'security_modsec_max_filter_colors' => 100,  // INCREASED: Allow 100 colors
            'security_modsec_max_filter_sizes' => 100,   // INCREASED: Allow 100 sizes
            'security_modsec_max_total_filters' => 200,  // INCREASED: Allow 200 total filters
            'security_modsec_max_query_length' => 5000   // INCREASED: Allow 5000 chars
        );

        foreach ($default_options as $option => $value) {
            if (get_option($option) === false) {
                update_option($option, $value);
            }
        }
        
        // Force create tables
        $this->force_create_tables();
        
        // Clear any existing blocks
        $this->clear_all_blocks();
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }

    public function deactivate_plugin() {
        // Clear scheduled events
        wp_clear_scheduled_hook('waf_cleanup_logs');
        wp_clear_scheduled_hook('bot_blackhole_cleanup');
        wp_clear_scheduled_hook('bot_blocker_cleanup');
        wp_clear_scheduled_hook('bot_protection_cleanup');
        
        // Clear all blocks when deactivating
        $this->clear_all_blocks();
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }

    private function clear_all_blocks() {
        global $wpdb;
        
        // Clear all transient blocks
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'bot_blocked_%'");
        
        // Clear WAF blocks
        delete_option('waf_blocked_ips');
        
        // Unblock your IPs specifically
        $this->clear_ip_blocks('103.251.55.45');
        $this->clear_ip_blocks('103.170.146.58');
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
wordfence
shiprocket
woocommerce
google
merchant';
    }

    public function init_components() {
        // CRITICAL: Skip ALL security components if this is an API request or Shiprocket request
        if ((defined('API_REQUEST_WHITELISTED') && API_REQUEST_WHITELISTED) ||
            (defined('SHIPROCKET_AUTH_REQUEST') && SHIPROCKET_AUTH_REQUEST) ||
            (defined('WC_API_REQUEST') && WC_API_REQUEST) ||
            (defined('SHIPROCKET_BYPASS_ACTIVE') && SHIPROCKET_BYPASS_ACTIVE) ||
            (defined('SECURITY_PLUGIN_DISABLED') && SECURITY_PLUGIN_DISABLED)) {
            return; // Don't load any security components
        }
        
        // Make sure user checks are initialized
        if ($this->is_admin === null) {
            $this->init_user_checks();
        }
        
        // Initialize components based on context
        if (!$this->is_admin && !$this->current_user_can_manage) {
            // Frontend components - only for non-admin users
            if (get_option('security_enable_xss', true)) {
                $this->headers = new SecurityHeaders();
                add_action('init', array($this->headers, 'add_security_headers'));
            }
            
            if (get_option('security_enable_cookie_banner', false) && !isset($_COOKIE['cookie_consent'])) {
                $this->cookie_consent = new CookieConsent();
            }
            
            if (get_option('security_enable_waf', true)) {
                $this->waf = new SecurityWAF();
            }
            
            // Initialize both bot protection systems
            if (get_option('security_enable_bot_protection', true)) {
                $this->bot_blackhole = new BotBlackhole();
            }
            
            if (get_option('security_enable_bot_blocking', true)) {
                $this->bot_blocker = new BotBlocker();
            }
        }

        // Always load these components
        $this->sanitization = new SecuritySanitization();
        $this->feature_manager = new FeatureManager();
        
        // Admin components
        if ($this->is_admin) {
            $this->settings = new SecuritySettings();
            add_action('admin_menu', array($this->settings, 'add_admin_menu'));
            add_action('admin_init', array($this->settings, 'register_settings'));
            
            // Initialize ModSecurity manager
            $this->modsecurity_manager = new ModSecurityManager();
            
            // Initialize bot dashboard - use BotBlackhole as primary
            if (get_option('security_enable_bot_protection', true)) {
                if (!$this->bot_blackhole) {
                    $this->bot_blackhole = new BotBlackhole();
                }
                $this->bot_dashboard = new BotDashboard($this->bot_blackhole);
                $this->bot_dashboard->init();
            } elseif (get_option('security_enable_bot_blocking', true)) {
                if (!$this->bot_blocker) {
                    $this->bot_blocker = new BotBlocker();
                }
                $this->bot_dashboard = new BotDashboard($this->bot_blocker);
                $this->bot_dashboard->init();
            }
        }
        
        // Initialize feature manager
        add_action('plugins_loaded', array($this->feature_manager, 'init'));
    }

    public function cleanup_waf_logs() {
        if ($this->waf) {
            $this->waf->cleanup_logs();
        }
    }
    
    public function cleanup_bot_logs() {
        if ($this->bot_blackhole) {
            $this->bot_blackhole->cleanup_logs();
        }
        if ($this->bot_blocker) {
            $this->bot_blocker->cleanup_old_logs();
        }
    }
}

// Initialize the plugin only if not completely disabled
if (!defined('SECURITY_PLUGIN_DISABLED') || !SECURITY_PLUGIN_DISABLED) {
    new CustomSecurityPlugin();
}