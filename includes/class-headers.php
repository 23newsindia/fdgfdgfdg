<?php
class SecurityHeaders {
    private static $headers_sent = false;
    private static $is_logged_in = null;
    private static $current_user_can_manage = null;
    
    public function __construct() {
        // Initialize static checks once for performance
        if (self::$is_logged_in === null) {
            self::$is_logged_in = is_user_logged_in();
        }
        
        if (self::$current_user_can_manage === null) {
            self::$current_user_can_manage = current_user_can('manage_options');
        }
    }
    
    public function add_security_headers() {
        if (self::$headers_sent || headers_sent() || !get_option('security_enable_xss', true)) {
            return;
        }
        
        // CRITICAL: Skip CSP headers for Shiprocket requests
        if ($this->is_shiprocket_request()) {
            $this->set_minimal_security_headers();
            return;
        }
        
        self::$headers_sent = true;
        $this->set_csp_headers();
        $this->set_security_headers();
    }

    private function is_shiprocket_request() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Check for Shiprocket indicators
        $shiprocket_indicators = array(
            'shiprocket',
            'woocommerce',
            '/wp-json/wc/',
            'consumer_key',
            'consumer_secret'
        );
        
        foreach ($shiprocket_indicators as $indicator) {
            if (stripos($user_agent, $indicator) !== false ||
                stripos($referer, $indicator) !== false ||
                stripos($request_uri, $indicator) !== false) {
                return true;
            }
        }
        
        // Check for WooCommerce REST API endpoints
        if (strpos($request_uri, '/wp-json/wc/') !== false) {
            return true;
        }
        
        // Check for authentication headers
        if (isset($_SERVER['HTTP_AUTHORIZATION']) || 
            isset($_GET['consumer_key']) || 
            isset($_POST['consumer_key'])) {
            return true;
        }
        
        return false;
    }

    private function set_minimal_security_headers() {
        // Set minimal headers for Shiprocket - no CSP restrictions
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // CRITICAL: Allow all origins for Shiprocket
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
        header('Access-Control-Allow-Credentials: true');
        
        // Remove potentially dangerous headers
        header_remove('Server');
        header_remove('X-Powered-By');
        
        self::$headers_sent = true;
    }

    private function set_csp_headers() {
        // Get CSP settings
        $enable_strict_csp = get_option('security_enable_strict_csp', false);
        $allow_adsense = get_option('security_allow_adsense', false);
        $allow_youtube = get_option('security_allow_youtube', false);
        $allow_twitter = get_option('security_allow_twitter', false);

        // Get custom domain settings
        $allowed_script_domains = array_filter(array_map('trim', explode("\n", get_option('security_allowed_script_domains', ''))));
        $allowed_style_domains = array_filter(array_map('trim', explode("\n", get_option('security_allowed_style_domains', ''))));
        $allowed_image_domains = array_filter(array_map('trim', explode("\n", get_option('security_allowed_image_domains', ''))));
        $allowed_frame_domains = array_filter(array_map('trim', explode("\n", get_option('security_allowed_frame_domains', ''))));

        // Get the site domain
        $site_domain = parse_url(get_site_url(), PHP_URL_HOST);

        // CRITICAL: Add Shiprocket domains to all CSP directives
        $shiprocket_domains = array(
            '*.shiprocket.in',
            'app.shiprocket.in',
            'apiv2.shiprocket.in',
            'api.shiprocket.in',
            'sr-posthog.shiprocket.in',
            'o4508657526439936.ingest.us.sentry.io'
        );

        // WordPress-specific CSP directives with more permissive defaults + Shiprocket
        $csp = array(
            "default-src" => array_merge(
                array("'self'", "https:", "data:", "blob:"),
                $shiprocket_domains
            ),
            "script-src" => array_merge(
                array(
                    "'self'",
                    "'unsafe-inline'",
                    "'unsafe-eval'",
                    "https:",
                    "blob:",
                    "*.wordpress.org",
                    "*.wp.com",
                    "*.google.com",
                    "*.googleapis.com",
                    "*.gstatic.com",
                    $site_domain
                ),
                $shiprocket_domains,
                $allowed_script_domains
            ),
            "style-src" => array_merge(
                array(
                    "'self'",
                    "'unsafe-inline'",
                    "https:",
                    "*.googleapis.com",
                    "*.gstatic.com",
                    $site_domain
                ),
                $shiprocket_domains,
                $allowed_style_domains
            ),
            "img-src" => array_merge(
                array(
                    "'self'",
                    "data:",
                    "https:",
                    "*.wp.com",
                    "*.wordpress.org",
                    "*.gravatar.com",
                    "*.googleusercontent.com",
                    "*.google.com",
                    "*.gstatic.com",
                    "*.bewakoof.com",
                    "form-ext.contlo.com",
                    $site_domain
                ),
                $shiprocket_domains,
                $allowed_image_domains
            ),
            "font-src" => array_merge(
                array("'self'", "data:", "https:", "*.gstatic.com", "*.googleapis.com"),
                $shiprocket_domains
            ),
            "connect-src" => array_merge(
                array("'self'", "https:", "*.google-analytics.com", "*.doubleclick.net", "blob:"),
                $shiprocket_domains
            ),
            "frame-src" => array_merge(
                array("'self'", "https:", "*.doubleclick.net", "*.google.com"),
                $shiprocket_domains,
                $allowed_frame_domains
            ),
            "object-src" => array("'none'"),
            "base-uri" => array("'self'"),
            "form-action" => array_merge(
                array("'self'", "https:"),
                $shiprocket_domains
            ),
            "frame-ancestors" => array("'self'"),
            "manifest-src" => array("'self'", "blob:")
        );

        // If strict CSP is enabled, use more restrictive rules but still allow Shiprocket
        if ($enable_strict_csp) {
            $csp["script-src"] = array_merge(
                array("'self'", "'unsafe-inline'", "'unsafe-eval'", "blob:"),
                array($site_domain, "*.wordpress.org", "*.wp.com"),
                $shiprocket_domains,
                $allowed_script_domains
            );
            
            $csp["style-src"] = array_merge(
                array("'self'", "'unsafe-inline'"),
                array($site_domain, "*.googleapis.com"),
                $shiprocket_domains,
                $allowed_style_domains
            );
            
            $csp["img-src"] = array_merge(
                array("'self'", "data:", "blob:"),
                array($site_domain, "*.wp.com", "*.gravatar.com", "*.bewakoof.com", "form-ext.contlo.com"),
                $shiprocket_domains,
                $allowed_image_domains
            );

            $csp["frame-src"] = array_merge(
                array("'self'", "blob:"),
                $shiprocket_domains,
                $allowed_frame_domains
            );

            // Add third-party service permissions
            if ($allow_adsense) {
                $csp["script-src"] = array_merge($csp["script-src"], 
                    array("*.google.com", "*.googleadservices.com", "*.googlesyndication.com")
                );
                $csp["img-src"] = array_merge($csp["img-src"], 
                    array("*.google.com", "*.googleusercontent.com", "*.doubleclick.net")
                );
                $csp["frame-src"] = array_merge($csp["frame-src"], 
                    array("*.google.com", "*.doubleclick.net")
                );
            }

            if ($allow_youtube) {
                $csp["frame-src"] = array_merge($csp["frame-src"], 
                    array("*.youtube.com", "*.youtube-nocookie.com")
                );
                $csp["img-src"] = array_merge($csp["img-src"], 
                    array("*.ytimg.com")
                );
            }

            if ($allow_twitter) {
                $csp["script-src"] = array_merge($csp["script-src"], 
                    array("*.twitter.com", "*.twimg.com")
                );
                $csp["frame-src"] = array_merge($csp["frame-src"], 
                    array("*.twitter.com")
                );
                $csp["img-src"] = array_merge($csp["img-src"], 
                    array("*.twimg.com", "*.twitter.com")
                );
            }
        }

        // Build CSP string
        $csp_string = "";
        foreach ($csp as $directive => $sources) {
            $csp_string .= $directive . " " . implode(" ", array_unique($sources)) . "; ";
        }

        // Add upgrade-insecure-requests
        $csp_string .= "upgrade-insecure-requests";

        header("Content-Security-Policy: " . $csp_string);
    }

    private function set_security_headers() {
        // Standard security headers
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Modern security headers with relaxed CORS policies for Shiprocket
        header('Permissions-Policy: accelerometer=(), camera=*, geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=*, usb=()');
        header('Cross-Origin-Opener-Policy: same-origin-allow-popups');
        header('Cross-Origin-Resource-Policy: cross-origin');
        
        // CRITICAL: Add CORS headers for Shiprocket
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
        header('Access-Control-Allow-Credentials: true');
        
        // Remove potentially dangerous headers
        header_remove('Server');
        header_remove('X-Powered-By');
    }
}