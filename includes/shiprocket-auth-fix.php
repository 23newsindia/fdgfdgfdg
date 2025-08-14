<?php
// includes/shiprocket-auth-fix.php
// Comprehensive Shiprocket Authentication Fix

if (!defined('ABSPATH')) {
    exit;
}

class ShiprocketAuthFix {
    private $shiprocket_domains = array(
        'app.shiprocket.in',
        'apiv2.shiprocket.in',
        'api.shiprocket.in',
        'shiprocket.in',
        'www.shiprocket.in',
        'sr-posthog.shiprocket.in',
        'o4508657526439936.ingest.us.sentry.io',
        'nexus-websocket-b.intercom.io',
        'twk-lausanne.com'
    );
    
    private $shiprocket_patterns = array(
        '/wp-json/wc/',
        '/wc-auth/',
        'consumer_key=',
        'consumer_secret=',
        'oauth_token=',
        'oauth_verifier=',
        'wc-api=',
        'rest_route=',
        'shiprocket'
    );
    
    public function __construct() {
        // Hook very early to catch authentication requests
        add_action('plugins_loaded', array($this, 'detect_shiprocket_auth'), 1);
        add_action('init', array($this, 'handle_shiprocket_auth'), 0);
        add_action('rest_api_init', array($this, 'whitelist_wc_auth'), 0);
        
        // Handle OAuth callbacks
        add_action('wp_loaded', array($this, 'handle_oauth_callback'), 1);
        
        // Add specific filters for WooCommerce auth
        add_filter('woocommerce_rest_check_permissions', array($this, 'allow_shiprocket_permissions'), 10, 4);
        add_filter('rest_authentication_errors', array($this, 'bypass_auth_for_shiprocket'), 5);
        
        // Disable security for OAuth flows
        add_action('template_redirect', array($this, 'disable_security_for_oauth'), 1);
    }
    
    public function detect_shiprocket_auth() {
        if ($this->is_shiprocket_request()) {
            // Define constants to bypass all security
            if (!defined('SHIPROCKET_AUTH_REQUEST')) {
                define('SHIPROCKET_AUTH_REQUEST', true);
            }
            if (!defined('API_REQUEST_WHITELISTED')) {
                define('API_REQUEST_WHITELISTED', true);
            }
            
            // Remove all security hooks immediately
            $this->remove_all_security_hooks();
            
            // Set permissive headers
            $this->set_permissive_headers();
        }
    }
    
    public function handle_shiprocket_auth() {
        if ($this->is_shiprocket_request()) {
            // Completely disable security for this request
            $this->disable_all_security();
            
            // Set CORS headers for Shiprocket
            $this->set_shiprocket_cors_headers();
        }
    }
    
    public function handle_oauth_callback() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Check for OAuth callback patterns
        if (strpos($request_uri, 'wc-auth') !== false || 
            strpos($request_uri, 'oauth') !== false ||
            isset($_GET['oauth_token']) ||
            isset($_GET['oauth_verifier']) ||
            isset($_GET['consumer_key'])) {
            
            // This is an OAuth callback - disable all security
            $this->disable_all_security();
            $this->set_shiprocket_cors_headers();
        }
    }
    
    public function whitelist_wc_auth() {
        // Whitelist all WooCommerce authentication endpoints
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        $wc_auth_patterns = array(
            '/wp-json/wc/',
            '/wc-auth/',
            '/wp-admin/admin.php?page=wc-settings',
            '/wp-admin/admin.php?page=wc-status'
        );
        
        foreach ($wc_auth_patterns as $pattern) {
            if (strpos($request_uri, $pattern) !== false) {
                $this->disable_all_security();
                return;
            }
        }
    }
    
    public function allow_shiprocket_permissions($permission, $context, $object_id, $object_type) {
        if ($this->is_shiprocket_request()) {
            return true; // Allow all permissions for Shiprocket
        }
        return $permission;
    }
    
    public function bypass_auth_for_shiprocket($error) {
        if ($this->is_shiprocket_request()) {
            return null; // No authentication error for Shiprocket
        }
        return $error;
    }
    
    public function disable_security_for_oauth() {
        if ($this->is_oauth_flow()) {
            $this->disable_all_security();
            $this->set_shiprocket_cors_headers();
        }
    }
    
    private function is_shiprocket_request() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Check user agent
        if (stripos($user_agent, 'shiprocket') !== false) {
            return true;
        }
        
        // Check referer for Shiprocket domains
        foreach ($this->shiprocket_domains as $domain) {
            if (stripos($referer, $domain) !== false || 
                stripos($origin, $domain) !== false) {
                return true;
            }
        }
        
        // Check request URI for Shiprocket patterns
        foreach ($this->shiprocket_patterns as $pattern) {
            if (stripos($request_uri, $pattern) !== false) {
                return true;
            }
        }
        
        // Check for OAuth parameters
        if (isset($_GET['consumer_key']) || 
            isset($_POST['consumer_key']) ||
            isset($_GET['oauth_token']) ||
            isset($_GET['oauth_verifier'])) {
            return true;
        }
        
        // Check for WooCommerce API authentication headers
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
            if (strpos($auth_header, 'OAuth') !== false || 
                strpos($auth_header, 'Basic') !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function is_oauth_flow() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        return (strpos($request_uri, 'wc-auth') !== false ||
                strpos($request_uri, 'oauth') !== false ||
                isset($_GET['oauth_token']) ||
                isset($_GET['oauth_verifier']) ||
                isset($_GET['consumer_key']) ||
                isset($_GET['consumer_secret']));
    }
    
    private function disable_all_security() {
        // Remove WAF hooks
        remove_action('init', array('SecurityWAF', 'waf_check'));
        
        // Remove bot protection hooks
        remove_action('init', array('BotBlackhole', 'check_bot_access'));
        remove_action('init', array('BotBlocker', 'check_bot_request'));
        remove_action('wp', array('BotBlackhole', 'capture_live_traffic'));
        
        // Remove header hooks
        remove_action('send_headers', array('SecurityHeaders', 'add_security_headers'));
        remove_action('init', array('SecurityHeaders', 'add_security_headers'));
        
        // Remove feature manager hooks
        remove_action('parse_request', array('FeatureManager', 'remove_query_strings'));
        remove_action('init', array('FeatureManager', 'check_url_security'));
        remove_action('init', array('FeatureManager', 'block_direct_php_access'));
        
        // Disable rate limiting
        add_filter('woocommerce_rest_check_permissions', '__return_true', 999);
        
        // Allow all REST API access
        add_filter('rest_authentication_errors', '__return_null', 999);
    }
    
    private function remove_all_security_hooks() {
        global $wp_filter;
        
        // Remove all security-related hooks
        $security_hooks = array(
            'init' => array('SecurityWAF', 'BotBlackhole', 'BotBlocker', 'FeatureManager'),
            'wp' => array('BotBlackhole'),
            'send_headers' => array('SecurityHeaders'),
            'parse_request' => array('FeatureManager'),
            'rest_api_init' => array('SecurityWAF', 'BotBlackhole')
        );
        
        foreach ($security_hooks as $hook => $classes) {
            if (isset($wp_filter[$hook])) {
                foreach ($wp_filter[$hook]->callbacks as $priority => $callbacks) {
                    foreach ($callbacks as $callback_id => $callback) {
                        if (is_array($callback['function']) && is_object($callback['function'][0])) {
                            $class_name = get_class($callback['function'][0]);
                            foreach ($classes as $security_class) {
                                if (strpos($class_name, $security_class) !== false) {
                                    unset($wp_filter[$hook]->callbacks[$priority][$callback_id]);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    private function set_permissive_headers() {
        if (headers_sent()) {
            return;
        }
        
        // Set very permissive headers for Shiprocket
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH');
        header('Access-Control-Allow-Headers: *');
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Max-Age: 86400');
        
        // Remove restrictive headers
        header_remove('Content-Security-Policy');
        header_remove('X-Frame-Options');
        header_remove('X-Content-Type-Options');
    }
    
    private function set_shiprocket_cors_headers() {
        if (headers_sent()) {
            return;
        }
        
        // Handle preflight requests
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            $this->set_permissive_headers();
            http_response_code(200);
            exit;
        }
        
        $this->set_permissive_headers();
    }
}

// Initialize the fix
new ShiprocketAuthFix();