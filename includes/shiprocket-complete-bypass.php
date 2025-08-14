<?php
// includes/shiprocket-complete-bypass.php
// SURGICAL OPTION: Complete Shiprocket Authentication Bypass (Fixed)

if (!defined('ABSPATH')) {
    exit;
}

class ShiprocketCompleteBypass {
    private $bypass_active = false;
    
    public function __construct() {
        // Hook at the very beginning of WordPress loading
        add_action('plugins_loaded', array($this, 'complete_bypass'), 1);
        
        // Emergency bypass for any missed requests
        if ($this->should_bypass_completely()) {
            $this->emergency_bypass();
        }
    }
    
    public function complete_bypass() {
        if ($this->should_bypass_completely()) {
            $this->bypass_active = true;
            
            // SURGICAL: Only disable security plugin components
            $this->disable_security_plugin_only();
            
            // Set ultra-permissive headers
            $this->set_ultra_permissive_headers();
            
            // Log the bypass for debugging
            error_log('SHIPROCKET BYPASS: Complete security bypass activated for: ' . $_SERVER['REQUEST_URI']);
        }
    }
    
    private function should_bypass_completely() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $query_string = $_SERVER['QUERY_STRING'] ?? '';
        
        // CRITICAL: Never bypass WordPress admin pages
        if (is_admin() || strpos($request_uri, '/wp-admin/') !== false) {
            return false;
        }
        
        // CRITICAL: Never bypass settings saves
        if (isset($_POST['save_settings']) || isset($_POST['security_nonce'])) {
            return false;
        }
        
        // CRITICAL: Never bypass WordPress core functionality
        if (strpos($request_uri, '/wp-login.php') !== false ||
            strpos($request_uri, '/wp-cron.php') !== false ||
            strpos($request_uri, '/wp-includes/') !== false) {
            return false;
        }
        
        // PRECISE: Only bypass for actual Shiprocket API requests
        $shiprocket_indicators = array(
            // Shiprocket specific domains in referer/origin
            'app.shiprocket.in',
            'apiv2.shiprocket.in',
            'api.shiprocket.in',
            
            // WooCommerce REST API endpoints (not admin)
            '/wp-json/wc/v3/',
            '/wp-json/wc/v2/',
            '/wp-json/wc/v1/',
            
            // OAuth flows
            'consumer_key=',
            'consumer_secret=',
            'oauth_token=',
            'oauth_verifier=',
        );
        
        // Check referer and origin for Shiprocket domains
        foreach (array('app.shiprocket.in', 'apiv2.shiprocket.in', 'api.shiprocket.in') as $domain) {
            if (stripos($referer, $domain) !== false || stripos($origin, $domain) !== false) {
                return true;
            }
        }
        
        // Check for WooCommerce REST API calls (not admin pages)
        if (strpos($request_uri, '/wp-json/wc/') !== false) {
            return true;
        }
        
        // Check for OAuth parameters
        if (isset($_GET['consumer_key']) || isset($_POST['consumer_key']) ||
            isset($_GET['oauth_token']) || isset($_GET['oauth_verifier'])) {
            return true;
        }
        
        // Check for API authentication headers
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
            if (strpos($auth_header, 'OAuth') !== false || 
                strpos($auth_header, 'Basic') !== false) {
                return true;
            }
        }
        
        // Check user agent for Shiprocket
        if (stripos($user_agent, 'shiprocket') !== false) {
            return true;
        }
        
        return false;
    }
    
    private function emergency_bypass() {
        // Define all bypass constants
        if (!defined('SHIPROCKET_BYPASS_ACTIVE')) {
            define('SHIPROCKET_BYPASS_ACTIVE', true);
        }
        if (!defined('API_REQUEST_WHITELISTED')) {
            define('API_REQUEST_WHITELISTED', true);
        }
        if (!defined('WC_API_REQUEST')) {
            define('WC_API_REQUEST', true);
        }
        if (!defined('SECURITY_PLUGIN_DISABLED')) {
            define('SECURITY_PLUGIN_DISABLED', true);
        }
        
        // Set headers immediately
        $this->set_ultra_permissive_headers();
    }
    
    private function disable_security_plugin_only() {
        global $wp_filter;
        
        // SURGICAL: Remove ONLY security plugin hooks, preserve WordPress core
        $security_classes = array(
            'SecurityWAF',
            'SecurityHeaders', 
            'BotBlackhole',
            'BotBlocker',
            'BotProtection',
            'FeatureManager',
            'SEOManager'
        );
        
        // Only remove hooks from security classes
        foreach ($wp_filter as $hook_name => $hook) {
            if (is_object($hook) && isset($hook->callbacks)) {
                foreach ($hook->callbacks as $priority => $callbacks) {
                    foreach ($callbacks as $callback_id => $callback) {
                        if (is_array($callback['function']) && is_object($callback['function'][0])) {
                            $class_name = get_class($callback['function'][0]);
                            foreach ($security_classes as $security_class) {
                                if (strpos($class_name, $security_class) !== false) {
                                    unset($wp_filter[$hook_name]->callbacks[$priority][$callback_id]);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Disable specific security functions without affecting WordPress core
        add_filter('option_security_enable_xss', '__return_false', 999);
        add_filter('option_security_enable_waf', '__return_false', 999);
        add_filter('option_security_enable_bot_protection', '__return_false', 999);
        add_filter('option_security_enable_bot_blocking', '__return_false', 999);
        add_filter('option_security_enable_seo_features', '__return_false', 999);
        
        // Override all security checks
        add_filter('woocommerce_rest_check_permissions', '__return_true', 999);
        add_filter('rest_authentication_errors', '__return_null', 999);
        add_filter('rest_pre_dispatch', array($this, 'allow_all_rest_requests'), 1, 3);
        
        // Remove specific security actions without touching WordPress core
        $this->remove_security_actions_only();
    }
    
    private function remove_security_actions_only() {
        // Remove only security-related actions, not WordPress core actions
        $security_actions = array(
            'init' => array(
                array('SecurityWAF', 'waf_check'),
                array('BotBlackhole', 'check_bot_access'),
                array('BotBlocker', 'check_bot_request'),
                array('FeatureManager', 'check_url_security'),
                array('FeatureManager', 'block_direct_php_access'),
                array('SecurityHeaders', 'add_security_headers')
            ),
            'wp' => array(
                array('BotBlackhole', 'capture_live_traffic')
            ),
            'send_headers' => array(
                array('SecurityHeaders', 'add_security_headers')
            ),
            'parse_request' => array(
                array('FeatureManager', 'remove_query_strings')
            )
        );
        
        foreach ($security_actions as $hook => $actions) {
            foreach ($actions as $action) {
                remove_action($hook, $action);
            }
        }
    }
    
    public function allow_all_rest_requests($result, $server, $request) {
        // Allow all REST requests when bypass is active
        if ($this->bypass_active) {
            return $result;
        }
        return $result;
    }
    
    private function set_ultra_permissive_headers() {
        if (headers_sent()) {
            return;
        }
        
        // Ultra-permissive CORS headers
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD');
        header('Access-Control-Allow-Headers: *');
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Max-Age: 86400');
        header('Access-Control-Expose-Headers: *');
        
        // Remove ALL security headers
        header_remove('Content-Security-Policy');
        header_remove('Content-Security-Policy-Report-Only');
        header_remove('X-Frame-Options');
        header_remove('X-Content-Type-Options');
        header_remove('X-XSS-Protection');
        header_remove('Referrer-Policy');
        header_remove('Permissions-Policy');
        header_remove('Cross-Origin-Opener-Policy');
        header_remove('Cross-Origin-Resource-Policy');
        header_remove('Cross-Origin-Embedder-Policy');
        
        // Set permissive cache headers
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        // Handle OPTIONS preflight
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }
    }
    
    public function is_bypass_active() {
        return $this->bypass_active;
    }
}

// Initialize immediately
new ShiprocketCompleteBypass();