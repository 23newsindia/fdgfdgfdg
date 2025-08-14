<?php
// includes/woocommerce-auth-bypass.php
// Specific WooCommerce Authentication Bypass for Shiprocket (Fixed)

if (!defined('ABSPATH')) {
    exit;
}

class WooCommerceAuthBypass {
    public function __construct() {
        // Hook very early to catch WooCommerce auth requests
        add_action('plugins_loaded', array($this, 'init'), 1);
        add_action('rest_api_init', array($this, 'bypass_wc_auth'), 1);
        add_filter('woocommerce_rest_check_permissions', array($this, 'allow_all_wc_permissions'), 1, 4);
        add_filter('rest_authentication_errors', array($this, 'bypass_rest_auth'), 1);
        
        // Handle OAuth specifically
        add_action('wp_loaded', array($this, 'handle_wc_oauth'), 1);
        add_action('template_redirect', array($this, 'handle_wc_auth_page'), 1);
    }
    
    public function init() {
        // Check if this is a WooCommerce API request
        if ($this->is_wc_api_request()) {
            // Disable security for WC API without affecting WordPress core
            $this->disable_security_for_wc_api();
        }
    }
    
    public function bypass_wc_auth() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Bypass authentication for all WC endpoints
        if (strpos($request_uri, '/wp-json/wc/') !== false) {
            add_filter('rest_authentication_errors', '__return_null', 999);
            add_filter('woocommerce_rest_check_permissions', '__return_true', 999);
        }
    }
    
    public function allow_all_wc_permissions($permission, $context, $object_id, $object_type) {
        // Allow all WooCommerce permissions for API requests
        if ($this->is_wc_api_request() || $this->is_shiprocket_request()) {
            return true;
        }
        return $permission;
    }
    
    public function bypass_rest_auth($error) {
        // Bypass REST authentication for WC API and Shiprocket
        if ($this->is_wc_api_request() || $this->is_shiprocket_request()) {
            return null;
        }
        return $error;
    }
    
    public function handle_wc_oauth() {
        // Handle WooCommerce OAuth flow
        if (isset($_GET['wc-auth-version']) || 
            isset($_GET['consumer_key']) || 
            isset($_GET['consumer_secret'])) {
            
            $this->disable_security_only();
            $this->set_oauth_headers();
        }
    }
    
    public function handle_wc_auth_page() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Handle WooCommerce auth page
        if (strpos($request_uri, 'wc-auth') !== false) {
            $this->disable_security_only();
            $this->set_oauth_headers();
        }
    }
    
    private function is_wc_api_request() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        return (strpos($request_uri, '/wp-json/wc/') !== false ||
                strpos($request_uri, 'wc-api=') !== false ||
                strpos($request_uri, 'wc-auth') !== false ||
                isset($_GET['consumer_key']) ||
                isset($_POST['consumer_key']));
    }
    
    private function is_shiprocket_request() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        
        $shiprocket_indicators = array('shiprocket', 'apiv2.shiprocket.in', 'app.shiprocket.in');
        
        foreach ($shiprocket_indicators as $indicator) {
            if (stripos($user_agent, $indicator) !== false ||
                stripos($referer, $indicator) !== false ||
                stripos($origin, $indicator) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function disable_security_for_wc_api() {
        // Define bypass constants
        if (!defined('WC_API_REQUEST')) {
            define('WC_API_REQUEST', true);
        }
        if (!defined('API_REQUEST_WHITELISTED')) {
            define('API_REQUEST_WHITELISTED', true);
        }
        
        $this->disable_security_only();
    }
    
    private function disable_security_only() {
        // FIXED: Only remove security hooks, not WordPress core hooks
        $security_hooks_to_remove = array(
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
        
        // Remove only security-related hooks
        foreach ($security_hooks_to_remove as $hook => $actions) {
            foreach ($actions as $action) {
                remove_action($hook, $action);
            }
        }
        
        // Disable rate limiting
        add_filter('woocommerce_rest_check_permissions', '__return_true', 999);
        add_filter('rest_authentication_errors', '__return_null', 999);
    }
    
    private function set_oauth_headers() {
        if (headers_sent()) {
            return;
        }
        
        // Set OAuth-friendly headers
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With');
        header('Access-Control-Allow-Credentials: true');
        
        // Remove security headers that might interfere
        header_remove('Content-Security-Policy');
        header_remove('X-Frame-Options');
        header_remove('X-Content-Type-Options');
        
        // Handle preflight
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }
    }
}

// Initialize the bypass
new WooCommerceAuthBypass();