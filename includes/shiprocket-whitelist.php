<?php
// includes/shiprocket-whitelist.php
// API Whitelist for Security Plugin (Shiprocket, Google Merchant, WooCommerce)

if (!defined('ABSPATH')) {
    exit;
}

class APIWhitelist {
    private $api_domains = array(
        // Shiprocket domains
        'app.shiprocket.in',
        'apiv2.shiprocket.in',
        'api.shiprocket.in',
        'shiprocket.in',
        'www.shiprocket.in',
        'sr-posthog.shiprocket.in',
        'o4508657526439936.ingest.us.sentry.io', 
        'nexus-websocket-b.intercom.io',         
        'twk-lausanne.com', // Fixed domain (added .com)
        
        // Google domains
        'accounts.google.com',
        'oauth2.googleapis.com',
        'www.googleapis.com',
        'merchantcenter.googleapis.com',
        'content.googleapis.com',
        'shopping.googleapis.com',
        'jetpack.wordpress.com',
        'jetpack.com',
        'public-api.wordpress.com',
        
        // Additional domains
        'form-ext.contlo.com',
        '*.bewakoof.com'
    );
    
    private $api_ips = array(
        // Shiprocket IP ranges
        '52.66.0.0/16',
        '13.126.0.0/16',
        '13.232.0.0/16',
        '35.154.0.0/16',       
        '3.7.0.0/16',
        '15.207.0.0/16', // Additional Shiprocket range
        '65.0.0.0/16'    // Additional range
    );
    
    public function __construct() {
        // Hook early to bypass all security checks for API requests
        add_action('plugins_loaded', array($this, 'whitelist_api_requests'), 1);
        
        // Handle OPTIONS requests for CORS
        add_action('init', array($this, 'handle_cors_preflight'), 0);
        
        // Add specific WooCommerce admin hooks
        add_action('rest_api_init', array($this, 'whitelist_wc_admin_routes'), 1);
    }
    
    public function handle_cors_preflight() {
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            $this->add_cors_headers(true);
            exit(0);
        }
    }
    
    public function whitelist_wc_admin_routes() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        $wc_admin_routes = array(
            '/wp-json/wc/gla/',
            '/wp-json/wc/v3/',
            '/wp-json/wc/v2/',
            '/wp-json/wc/v1/',
            '/wp-json/wc-admin/',
            '/wp-json/jetpack/',
            '/wp-admin/admin.php?page=wc-admin',
            '/wp-json/shiprocket/' // Added Shiprocket API endpoint
        );
        
        foreach ($wc_admin_routes as $route) {
            if (strpos($request_uri, $route) !== false) {
                define('API_REQUEST_WHITELISTED', true);
                $this->add_cors_headers();
                return;
            }
        }
    }
    
    public function whitelist_api_requests() {
        if ($this->is_api_request()) {
            define('API_REQUEST_WHITELISTED', true);
            $this->add_cors_headers();
            
            // Remove security hooks
            $this->remove_security_hooks();
        }
    }
    
    private function remove_security_hooks() {
        remove_action('init', array('SecurityWAF', 'waf_check'));
        remove_action('init', array('BotBlackhole', 'check_bot_access'));
        remove_action('init', array('BotBlocker', 'check_bot_request'));
        
        // Also remove CSP headers for API endpoints
        remove_action('send_headers', array('SecurityHeaders', 'add_security_headers'));
    }
    
    private function add_cors_headers($is_preflight = false) {
        if (headers_sent()) {
            return;
        }

        // Special headers for PostHog
        if ($this->is_posthog_request()) {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-WP-Nonce, X-PostHog-Session-Id, X-PostHog-Token');
            header('Access-Control-Allow-Credentials: true');
            if ($is_preflight) {
                header('Access-Control-Max-Age: 86400');
            }
            return;
        }

        // Standard API headers
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-WP-Nonce');
        header('Access-Control-Allow-Credentials: true');
        if ($is_preflight) {
            header('Access-Control-Max-Age: 86400');
        }
    }
    
    private function is_posthog_request() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        return strpos($request_uri, '/sr-posthog/') !== false || 
               strpos($request_uri, '/decide/') !== false ||
               strpos($request_uri, '/e/') !== false;
    }
    
    private function is_api_request() {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        
        // 1. First check for PostHog endpoints
        if ($this->is_posthog_request()) {
            return true;
        }
        
        // 2. Check for Shiprocket domains in origin
        $shiprocket_domains = array(
            'app.shiprocket.in',
            'apiv2.shiprocket.in',
            'api.shiprocket.in'
        );
        
        foreach ($shiprocket_domains as $domain) {
            if (stripos($origin, $domain) !== false) {
                return true;
            }
        }
        
        // 3. Check for API indicators in URL
        $api_indicators = array(
            '/wp-json/wc/',
            '/wp-json/shiprocket/',
            '/sr-api/',
            'consumer_key=',
            'consumer_secret='
        );
        
        foreach ($api_indicators as $indicator) {
            if (stripos($request_uri, $indicator) !== false) {
                return true;
            }
        }
        
        // 4. Check for authentication headers
        if (isset($_SERVER['HTTP_AUTHORIZATION']) || 
            isset($_GET['consumer_key']) || 
            isset($_POST['consumer_key'])) {
            return true;
        }
        
        return false;
    }
}

new APIWhitelist();