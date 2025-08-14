<?php
// includes/class-seo-manager.php

if (!defined('ABSPATH')) {
    exit;
}

class SEOManager {
    private $options_cache = array();
    
    private function get_option($key, $default = false) {
        if (!isset($this->options_cache[$key])) {
            $this->options_cache[$key] = get_option($key, $default);
        }
        return $this->options_cache[$key];
    }

    private function is_woocommerce_active() {
        return class_exists('WooCommerce');
    }

    public function init() {
        // CRITICAL: Run spam detection BEFORE any security checks
        add_action('plugins_loaded', array($this, 'handle_spam_urls'), 1);
        add_action('init', array($this, 'handle_spam_urls'), 1);
        add_action('template_redirect', array($this, 'handle_410_responses'), 1);
        add_action('wp_trash_post', array($this, 'store_deleted_post_url'));
        add_action('before_delete_post', array($this, 'store_deleted_post_url'));
        
        // NEW: Add WooCommerce no products detection - ENHANCED
        if ($this->is_woocommerce_active()) {
            add_action('woocommerce_no_products_found', array($this, 'handle_no_products_410'));
            add_action('template_redirect', array($this, 'check_no_products_on_shop_pages'), 5);
        }
        
        // Add admin hooks for 410 management
        add_action('admin_init', array($this, 'add_410_meta_box_hooks'));
        add_action('save_post', array($this, 'save_410_meta_box'));
        
        // Add bulk action for 410
        add_filter('bulk_actions-edit-post', array($this, 'add_410_bulk_action'));
        add_filter('bulk_actions-edit-page', array($this, 'add_410_bulk_action'));
        add_filter('handle_bulk_actions-edit-post', array($this, 'handle_410_bulk_action'), 10, 3);
        add_filter('handle_bulk_actions-edit-page', array($this, 'handle_410_bulk_action'), 10, 3);
        
        // Add spam logs submenu properly
        add_action('admin_menu', array($this, 'add_spam_logs_menu'), 20);
        
        // FIXED: Add rewrite rules for secure 410 page - HIGHER PRIORITY
        add_action('init', array($this, 'add_410_rewrite_rules'), 5);
        add_filter('query_vars', array($this, 'add_410_query_vars'));
        add_action('template_redirect', array($this, 'handle_410_endpoint'), 1);
        
        // FIXED: Add direct URL handling for /security-410/
        add_action('parse_request', array($this, 'handle_direct_410_request'), 1);
        
        // Add caching headers
        add_action('wp_headers', array($this, 'add_410_cache_headers'));
        
        // Force flush rewrite rules on activation
        add_action('wp_loaded', array($this, 'maybe_flush_rewrite_rules'));
    }

    // ENHANCED: Check for no products on WooCommerce shop pages
    public function check_no_products_on_shop_pages() {
        if (!$this->is_woocommerce_active()) {
            return;
        }

        // Only check on shop/category pages with filters
        if (!is_shop() && !is_product_category() && !is_product_tag()) {
            return;
        }

        // Only check if there are filter parameters
        if (empty($_GET) || !$this->has_filter_parameters($_GET)) {
            return;
        }

        // ENHANCED: Check if WooCommerce query has no products
        global $wp_query;
        
        if (isset($wp_query->found_posts) && $wp_query->found_posts == 0) {
            $this->send_410_response('No products found for filter combination');
        }
        
        // Alternative check using WooCommerce globals
        global $woocommerce_loop;
        if (isset($woocommerce_loop['total']) && $woocommerce_loop['total'] == 0) {
            $this->send_410_response('No products found for filter combination');
        }
        
        // Check using WC functions if available
        if (function_exists('wc_get_loop_prop')) {
            $total = wc_get_loop_prop('total');
            if ($total === 0) {
                $this->send_410_response('No products found for filter combination');
            }
        }
    }

    // NEW: Handle WooCommerce no products found hook
    public function handle_no_products_410() {
        // Only trigger 410 if there are filter parameters
        if (!empty($_GET) && $this->has_filter_parameters($_GET)) {
            $this->send_410_response('No products found for filter combination');
        }
    }

    // NEW: Check if request has filter parameters
    private function has_filter_parameters($params) {
        $filter_params = array('filter_colour', 'filter_color', 'filter_size', 'filter_brand', 'filter_price');
        
        foreach ($filter_params as $filter) {
            if (isset($params[$filter]) && !empty($params[$filter])) {
                return true;
            }
        }
        
        return false;
    }

    // FIXED: Add secure 410 endpoint without exposing plugin directory
    public function add_410_rewrite_rules() {
        // Add multiple rewrite rules for 410 page
        add_rewrite_rule(
            '^security-410/?$',
            'index.php?security_410=1',
            'top'
        );
        
        add_rewrite_rule(
            '^410/?$',
            'index.php?security_410=1',
            'top'
        );
        
        add_rewrite_rule(
            '^gone/?$',
            'index.php?security_410=1',
            'top'
        );
    }
    
    public function add_410_query_vars($vars) {
        $vars[] = 'security_410';
        return $vars;
    }
    
    // FIXED: Handle direct URL requests for /security-410/
    public function handle_direct_410_request($wp) {
        $request_uri = $_SERVER['REQUEST_URI'];
        
        // Check if this is a direct request to our 410 endpoints
        if (preg_match('#^/?(security-410|410|gone)/?(\?.*)?$#', $request_uri)) {
            // Set the query var manually
            $wp->query_vars['security_410'] = '1';
            
            // Serve the 410 page immediately
            $this->serve_cached_410_page();
        }
    }
    
    public function handle_410_endpoint() {
        if (get_query_var('security_410')) {
            $this->serve_cached_410_page();
        }
    }
    
    public function add_410_cache_headers($headers) {
        if (get_query_var('security_410') || $this->is_410_request()) {
            // Add aggressive caching for 410 pages
            $headers['Cache-Control'] = 'public, max-age=86400, s-maxage=86400'; // 24 hours
            $headers['Expires'] = gmdate('D, d M Y H:i:s', time() + 86400) . ' GMT';
            $headers['Pragma'] = 'cache';
            $headers['Vary'] = 'Accept-Encoding';
            $headers['X-Cache-Status'] = 'cached-410';
        }
        return $headers;
    }
    
    private function is_410_request() {
        $request_uri = $_SERVER['REQUEST_URI'];
        return preg_match('#^/?(security-410|410|gone)/?(\?.*)?$#', $request_uri);
    }
    
    public function maybe_flush_rewrite_rules() {
        if (!get_option('security_410_rules_flushed_v2')) {
            flush_rewrite_rules(false);
            update_option('security_410_rules_flushed_v2', true);
        }
    }
    
    private function serve_cached_410_page() {
        // Check cache first
        $cache_key = 'security_410_page_cache_v2';
        $cached_content = get_transient($cache_key);
        
        if ($cached_content !== false) {
            // Serve from cache
            $this->send_410_headers();
            echo $cached_content;
            exit;
        }
        
        // Generate and cache the 410 page
        $content = $this->generate_stylish_410_page();
        
        // Cache for 24 hours
        set_transient($cache_key, $content, 24 * HOUR_IN_SECONDS);
        
        // Serve the content
        $this->send_410_headers();
        echo $content;
        exit;
    }
    
    private function send_410_headers() {
        if (!headers_sent()) {
            status_header(410);
            header('HTTP/1.1 410 Gone');
            header('Status: 410 Gone');
            header('Content-Type: text/html; charset=utf-8');
            header('X-Robots-Tag: noindex, nofollow');
            header('X-Content-Security: blocked');
            
            // Add caching headers for performance
            header('Cache-Control: public, max-age=86400, s-maxage=86400');
            header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 86400) . ' GMT');
            header('Pragma: cache');
            header('Vary: Accept-Encoding');
            header('X-Cache-Status: cached-410');
            
            // SEO headers
            header('X-SEO-Status: 410-gone');
            header('X-Security-Block: spam-filter-protection');
        }
    }
    
    private function generate_stylish_410_page() {
        $site_name = get_bloginfo('name') ?: 'Wild Dragon';
        $home_url = home_url() ?: 'https://wilddragon.in';
        $site_description = get_bloginfo('description') ?: 'Premium Fashion & Lifestyle Brand';
        $custom_410_content = $this->get_option('security_410_page_content', '');
        
        if (!empty($custom_410_content)) {
            return $custom_410_content;
        }
        
        // Get current URL for logging
        $current_url = $_SERVER['REQUEST_URI'] ?? '/security-410/';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $ip = $this->get_client_ip();
        
        // Log this 410 request
        $this->log_410_request($current_url, $ip, $user_agent);
        
        // Enhanced stylish 410 page with modern design
        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>410 - Content Gone | <?php echo esc_html($site_name); ?></title>
            <meta name="robots" content="noindex, nofollow">
            <meta name="description" content="The requested content has been permanently removed from <?php echo esc_attr($site_name); ?>">
            <link rel="canonical" href="<?php echo esc_url($home_url); ?>">
            
            <!-- Open Graph -->
            <meta property="og:title" content="410 - Content Gone | <?php echo esc_attr($site_name); ?>">
            <meta property="og:description" content="The requested content has been permanently removed">
            <meta property="og:url" content="<?php echo esc_url($home_url . '/security-410/'); ?>">
            <meta property="og:type" content="website">
            <meta property="og:site_name" content="<?php echo esc_attr($site_name); ?>">
            
            <!-- Twitter Card -->
            <meta name="twitter:card" content="summary">
            <meta name="twitter:title" content="410 - Content Gone | <?php echo esc_attr($site_name); ?>">
            <meta name="twitter:description" content="The requested content has been permanently removed">
            
            <!-- Preload critical resources -->
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
            
            <style>
                :root {
                    --primary-color: #1a1a2e;
                    --secondary-color: #16213e;
                    --accent-color: #0f3460;
                    --error-color: #e74c3c;
                    --warning-color: #f39c12;
                    --success-color: #27ae60;
                    --text-primary: #2c3e50;
                    --text-secondary: #7f8c8d;
                    --text-light: #bdc3c7;
                    --bg-light: #f8f9fa;
                    --border-color: #ecf0f1;
                    --shadow-light: 0 2px 10px rgba(0,0,0,0.1);
                    --shadow-medium: 0 4px 20px rgba(0,0,0,0.15);
                    --shadow-heavy: 0 10px 40px rgba(0,0,0,0.2);
                    --gradient-primary: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 50%, var(--accent-color) 100%);
                    --gradient-error: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                    --gradient-warning: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
                }
                
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body { 
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
                    background: var(--gradient-primary);
                    color: var(--text-primary);
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    line-height: 1.6;
                    overflow-x: hidden;
                    position: relative;
                }
                
                /* Animated background */
                body::before {
                    content: '';
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: 
                        radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                        radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.3) 0%, transparent 50%),
                        radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.3) 0%, transparent 50%);
                    animation: float 20s ease-in-out infinite;
                    z-index: -1;
                }
                
                @keyframes float {
                    0%, 100% { transform: translateY(0px) rotate(0deg); }
                    33% { transform: translateY(-20px) rotate(1deg); }
                    66% { transform: translateY(20px) rotate(-1deg); }
                }
                
                .container { 
                    max-width: 800px; 
                    margin: 20px auto; 
                    background: rgba(255, 255, 255, 0.95);
                    backdrop-filter: blur(20px);
                    padding: 60px 50px; 
                    border-radius: 24px; 
                    box-shadow: var(--shadow-heavy);
                    position: relative;
                    overflow: hidden;
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }
                
                .container::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    height: 6px;
                    background: var(--gradient-error);
                    border-radius: 24px 24px 0 0;
                }
                
                .header {
                    text-align: center;
                    margin-bottom: 40px;
                }
                
                .logo {
                    font-size: 2.5em;
                    font-weight: 900;
                    color: var(--primary-color);
                    margin-bottom: 15px;
                    text-transform: uppercase;
                    letter-spacing: 3px;
                    background: var(--gradient-primary);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                }
                
                .status-code {
                    font-size: 10em;
                    font-weight: 900;
                    background: var(--gradient-error);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                    margin: 0 0 20px 0;
                    line-height: 0.8;
                    text-shadow: 0 4px 8px rgba(231, 76, 60, 0.3);
                    animation: pulse 2s ease-in-out infinite;
                }
                
                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.05); }
                }
                
                h1 { 
                    color: var(--text-primary); 
                    font-size: 3em;
                    margin: 0 0 20px 0;
                    font-weight: 700;
                    line-height: 1.2;
                }
                
                .subtitle {
                    font-size: 1.3em;
                    color: var(--text-secondary);
                    margin-bottom: 40px;
                    font-weight: 400;
                }
                
                .content-section {
                    margin: 40px 0;
                }
                
                .info-card {
                    background: var(--bg-light);
                    padding: 30px;
                    border-radius: 16px;
                    margin: 25px 0;
                    border-left: 5px solid var(--error-color);
                    position: relative;
                    overflow: hidden;
                }
                
                .info-card::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(45deg, transparent 0%, rgba(231, 76, 60, 0.05) 100%);
                    pointer-events: none;
                }
                
                .info-card h3 {
                    margin: 0 0 15px 0;
                    color: var(--error-color);
                    font-size: 1.4em;
                    font-weight: 600;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                
                .security-card {
                    background: linear-gradient(135deg, #fff3cd, #ffeaa7);
                    border-left-color: var(--warning-color);
                }
                
                .security-card h3 {
                    color: var(--warning-color);
                }
                
                .actions-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }
                
                .action-card {
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    box-shadow: var(--shadow-light);
                    border: 1px solid var(--border-color);
                    transition: all 0.3s ease;
                    text-align: center;
                }
                
                .action-card:hover {
                    transform: translateY(-5px);
                    box-shadow: var(--shadow-medium);
                    border-color: var(--primary-color);
                }
                
                .action-card .icon {
                    font-size: 2.5em;
                    margin-bottom: 15px;
                    display: block;
                }
                
                .action-card h4 {
                    margin: 0 0 10px 0;
                    color: var(--text-primary);
                    font-weight: 600;
                }
                
                .action-card p {
                    color: var(--text-secondary);
                    font-size: 0.9em;
                    margin: 0;
                }
                
                .cta-button { 
                    display: inline-block;
                    color: white;
                    background: var(--gradient-primary);
                    text-decoration: none; 
                    padding: 18px 35px;
                    border-radius: 12px;
                    font-weight: 600;
                    font-size: 1.1em;
                    transition: all 0.3s ease;
                    margin: 30px 15px 15px 15px;
                    box-shadow: var(--shadow-medium);
                    border: none;
                    cursor: pointer;
                    position: relative;
                    overflow: hidden;
                }
                
                .cta-button::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: -100%;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                    transition: left 0.5s;
                }
                
                .cta-button:hover::before {
                    left: 100%;
                }
                
                .cta-button:hover { 
                    transform: translateY(-3px);
                    box-shadow: 0 8px 25px rgba(26, 26, 46, 0.4);
                }
                
                .cta-button:active {
                    transform: translateY(-1px);
                }
                
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }
                
                .stat-item {
                    text-align: center;
                    padding: 20px;
                    background: white;
                    border-radius: 12px;
                    box-shadow: var(--shadow-light);
                }
                
                .stat-number {
                    font-size: 2.5em;
                    font-weight: 800;
                    color: var(--error-color);
                    display: block;
                    line-height: 1;
                }
                
                .stat-label {
                    font-size: 0.9em;
                    color: var(--text-secondary);
                    margin-top: 5px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                
                .footer {
                    margin-top: 50px;
                    padding-top: 30px;
                    border-top: 2px solid var(--border-color);
                    text-align: center;
                    color: var(--text-secondary);
                    font-size: 0.9em;
                }
                
                .footer .brand {
                    font-weight: 600;
                    color: var(--text-primary);
                    font-size: 1.1em;
                    margin-bottom: 5px;
                    display: block;
                }
                
                .cache-info {
                    position: absolute;
                    bottom: 15px;
                    right: 20px;
                    font-size: 0.7em;
                    color: var(--text-light);
                    opacity: 0.7;
                    background: rgba(255, 255, 255, 0.8);
                    padding: 5px 10px;
                    border-radius: 20px;
                }
                
                .tech-details {
                    background: #f8f9fa;
                    border: 1px solid #e9ecef;
                    border-radius: 8px;
                    padding: 15px;
                    margin: 20px 0;
                    font-family: 'Courier New', monospace;
                    font-size: 0.85em;
                    color: #495057;
                }
                
                .tech-details strong {
                    color: #212529;
                }
                
                /* Responsive Design */
                @media (max-width: 768px) {
                    .container {
                        padding: 40px 25px;
                        margin: 10px;
                        border-radius: 16px;
                    }
                    
                    .status-code {
                        font-size: 6em;
                    }
                    
                    h1 {
                        font-size: 2.2em;
                    }
                    
                    .logo {
                        font-size: 1.8em;
                    }
                    
                    .cta-button {
                        display: block;
                        margin: 20px 0;
                        text-align: center;
                    }
                    
                    .actions-grid {
                        grid-template-columns: 1fr;
                    }
                    
                    .stats-grid {
                        grid-template-columns: repeat(2, 1fr);
                    }
                }
                
                @media (max-width: 480px) {
                    .status-code {
                        font-size: 4em;
                    }
                    
                    h1 {
                        font-size: 1.8em;
                    }
                    
                    .stats-grid {
                        grid-template-columns: 1fr;
                    }
                }
                
                /* Loading animation */
                .loading-animation {
                    display: inline-block;
                    width: 20px;
                    height: 20px;
                    border: 3px solid rgba(231, 76, 60, 0.3);
                    border-radius: 50%;
                    border-top-color: var(--error-color);
                    animation: spin 1s ease-in-out infinite;
                }
                
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo"><?php echo esc_html($site_name); ?></div>
                    <div class="status-code">410</div>
                    <h1>Content Gone</h1>
                    <p class="subtitle">The requested content has been permanently removed</p>
                </div>
                
                <div class="content-section">
                    <div class="info-card">
                        <h3>🔍 What does HTTP 410 mean?</h3>
                        <p>A 410 "Gone" status indicates that the content you're looking for has been intentionally and permanently removed from our servers. Unlike a 404 error, this tells search engines that the content will not be coming back and should be removed from their index.</p>
                    </div>
                    
                    <div class="info-card security-card">
                        <h3>🛡️ Security Protection Active</h3>
                        <p>This request was blocked by our advanced security system. Our protection includes:</p>
                        <ul style="margin: 15px 0 0 20px; line-height: 1.8;">
                            <li>Spam filter URL detection with intelligent limits</li>
                            <li>Automated bot and scraper protection</li>
                            <li>Malicious request pattern blocking</li>
                            <li>Rate limiting and abuse prevention</li>
                            <li>Real-time threat analysis</li>
                        </ul>
                        
                        <div class="tech-details">
                            <strong>Request Details:</strong><br>
                            URL: <?php echo esc_html($current_url); ?><br>
                            Time: <?php echo date('Y-m-d H:i:s T'); ?><br>
                            Status: 410 Gone (Cached)<br>
                            Security: Active Protection
                        </div>
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-number">410</span>
                        <span class="stat-label">HTTP Status</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">24h</span>
                        <span class="stat-label">Cache Duration</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">SEO</span>
                        <span class="stat-label">Optimized</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">🔒</span>
                        <span class="stat-label">Secured</span>
                    </div>
                </div>
                
                <div class="actions-grid">
                    <div class="action-card">
                        <span class="icon">🏠</span>
                        <h4>Visit Homepage</h4>
                        <p>Return to our main page and explore our latest collections</p>
                    </div>
                    <div class="action-card">
                        <span class="icon">👕</span>
                        <h4>Men's Collection</h4>
                        <p>Discover our premium men's fashion and lifestyle products</p>
                    </div>
                    <div class="action-card">
                        <span class="icon">👗</span>
                        <h4>Women's Collection</h4>
                        <p>Browse our exclusive women's fashion and accessories</p>
                    </div>
                    <div class="action-card">
                        <span class="icon">🔍</span>
                        <h4>Search Products</h4>
                        <p>Use our advanced search to find exactly what you're looking for</p>
                    </div>
                </div>
                
                <div style="text-align: center;">
                    <a href="<?php echo esc_url($home_url); ?>" class="cta-button">
                        ← Return to <?php echo esc_html($site_name); ?> Homepage
                    </a>
                </div>
                
                <div class="footer">
                    <span class="brand"><?php echo esc_html($site_name); ?></span>
                    <span><?php echo esc_html($site_description); ?></span>
                </div>
                
                <div class="cache-info">
                    Cached: <?php echo date('Y-m-d H:i:s'); ?> | v2.0
                </div>
            </div>
            
            <!-- Structured Data for SEO -->
            <script type="application/ld+json">
            {
                "@context": "https://schema.org",
                "@type": "WebPage",
                "name": "410 - Content Gone",
                "description": "The requested content has been permanently removed",
                "url": "<?php echo esc_url($home_url . '/security-410/'); ?>",
                "mainEntity": {
                    "@type": "Thing",
                    "name": "HTTP 410 Gone",
                    "description": "Content permanently removed for security reasons"
                },
                "isPartOf": {
                    "@type": "WebSite",
                    "name": "<?php echo esc_js($site_name); ?>",
                    "url": "<?php echo esc_url($home_url); ?>",
                    "description": "<?php echo esc_js($site_description); ?>"
                },
                "publisher": {
                    "@type": "Organization",
                    "name": "<?php echo esc_js($site_name); ?>",
                    "url": "<?php echo esc_url($home_url); ?>"
                }
            }
            </script>
            
            <!-- Performance and SEO optimizations -->
            <script>
                // Preload critical resources
                if ('serviceWorker' in navigator) {
                    // Register service worker for caching (optional)
                }
                
                // Track 410 page views (optional analytics)
                if (typeof gtag !== 'undefined') {
                    gtag('event', '410_page_view', {
                        'event_category': 'Security',
                        'event_label': 'Content Gone',
                        'value': 1
                    });
                }
            </script>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    private function log_410_request($url, $ip, $user_agent) {
        $log_entry = array(
            'url' => $url,
            'reason' => 'Security 410 Page Access',
            'timestamp' => current_time('mysql'),
            'ip' => $ip,
            'user_agent' => $user_agent,
            'referer' => $_SERVER['HTTP_REFERER'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET'
        );
        
        $spam_logs = get_option('security_spam_url_logs', array());
        $spam_logs[] = $log_entry;
        
        // Keep only last 200 entries
        if (count($spam_logs) > 200) {
            $spam_logs = array_slice($spam_logs, -200);
        }
        
        update_option('security_spam_url_logs', $spam_logs);
    }

    public function handle_spam_urls() {
        // Skip admin area
        if (is_admin()) {
            return;
        }

        // CRITICAL: Skip for logged-in users with manage capabilities ONLY
        if (is_user_logged_in() && current_user_can('manage_options')) {
            return;
        }

        $current_url = $_SERVER['REQUEST_URI'];
        
        // PRIORITY 1: Check for custom blocked paths (like /shop/)
        if ($this->is_custom_blocked_path($current_url)) {
            $this->send_410_response('Custom blocked path - Content permanently removed');
        }
        
        // PRIORITY 2: Check for WooCommerce spam URLs - COMPLETELY REWRITTEN FOR ACCURACY
        if ($this->is_woocommerce_active()) {
            if ($this->is_spam_filter_url($current_url)) {
                $this->send_410_response('Spam filter URL detected - Content permanently removed');
            }
        }

        // PRIORITY 3: Handle excessive query parameters
        if ($this->has_excessive_query_params($current_url)) {
            $this->send_410_response('Excessive query parameters - Content permanently removed');
        }

        // PRIORITY 4: Check for manually marked 410 URLs
        if ($this->is_manual_410_url($current_url)) {
            $this->send_410_response('Content permanently removed');
        }
    }

    private function is_custom_blocked_path($url) {
        $blocked_paths = get_option('security_modsec_custom_blocked_paths', '/shop/');
        $paths = array_filter(array_map('trim', explode("\n", $blocked_paths)));
        
        $parsed_url = parse_url($url);
        $path = $parsed_url['path'] ?? '';
        
        foreach ($paths as $blocked_path) {
            if (strpos($path, $blocked_path) === 0) {
                $this->log_spam_attempt($url, "Custom blocked path: {$blocked_path}");
                return true;
            }
        }
        
        return false;
    }

    private function is_spam_filter_url($url) {
        // Only run if WooCommerce is active
        if (!$this->is_woocommerce_active()) {
            return false;
        }

        // Parse URL to get query parameters
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['query'])) {
            return false;
        }

        // FIXED: URL decode the query string FIRST to handle %2C properly
        $decoded_query = urldecode($parsed_url['query']);
        parse_str($decoded_query, $query_params);

        // Check if this is a product category or product page
        $path = $parsed_url['path'] ?? '';
        $is_product_page = (strpos($path, '/product-category/') !== false || strpos($path, '/product/') !== false);
        
        if (!$is_product_page) {
            return false;
        }

        // COMPLETELY REWRITTEN: ALLOW ALL LEGITIMATE COLORS - NO BLOCKING OF REAL COLORS
        
        // 1. Define ALL legitimate colors (MASSIVE EXPANDED LIST)
        $legitimate_colors = array(
            // Basic colors
            'black', 'white', 'red', 'blue', 'green', 'yellow', 'orange', 'purple', 'pink', 'brown',
            'grey', 'gray', 'navy', 'maroon', 'olive', 'lime', 'aqua', 'teal', 'silver', 'fuchsia',
            
            // Extended basic colors
            'navy-blue', 'aqua-blue', 'chocolate-brown', 'dark-green', 'light-blue', 'royal-blue',
            'forest-green', 'sky-blue', 'sea-green', 'wine-red', 'cream', 'beige', 'khaki', 'coral',
            'turquoise', 'violet', 'indigo', 'magenta', 'cyan', 'gold', 'bronze', 'copper',
            
            // FIXED: Add ALL your actual product colors
            'emerald-green', 'grey-melange', 'lavender', 'mint-green', 'sage-green', 'olive-green',
            'bottle-green', 'peace-orange', 'mustard-yellow', 'military-green', 'forest-green',
            'sea-green', 'lime-green', 'neon-green', 'dark-green', 'light-green', 'bright-green',
            
            // Fashion colors
            'rose-gold', 'champagne', 'burgundy', 'mauve', 'taupe', 'ivory', 'pearl', 'charcoal',
            'slate', 'stone', 'sand', 'rust', 'terracotta', 'salmon', 'peach', 'apricot',
            'blush', 'dusty-rose', 'powder-blue', 'baby-blue', 'periwinkle', 'lilac',
            
            // Trendy colors
            'millennial-pink', 'gen-z-yellow', 'classic-blue', 'living-coral', 'ultra-violet',
            'greenery', 'rose-quartz', 'serenity', 'marsala', 'radiant-orchid', 'emerald',
            'tangerine-tango', 'honeysuckle', 'turquoise', 'mimosa', 'blue-iris',
            
            // Melange and mixed colors
            'black-melange', 'white-melange', 'blue-melange', 'red-melange', 'green-melange',
            'yellow-melange', 'orange-melange', 'purple-melange', 'pink-melange', 'brown-melange',
            
            // Multi-word colors
            'off-white', 'jet-black', 'snow-white', 'fire-red', 'electric-blue', 'neon-yellow',
            'hot-pink', 'deep-purple', 'bright-orange', 'dark-brown', 'light-grey', 'dark-grey'
        );
        
        // 2. ONLY block if there are OBVIOUS spam patterns - NOT real colors
        $obvious_spam_patterns = array(
            // Only block if it contains obvious non-color spam
            'srsltid', 'gclid', 'fbclid', 'utm_', '_ga', '_gid', 'sessionid', 'userid',
            // Only block if it's clearly not a color (numbers, special chars, etc.)
            'color123', 'test123', 'spam123', 'bot123', 'hack123'
        );
        
        // 3. Check filter limits - INCREASED TO BE MORE PERMISSIVE
        $filter_limits = array(
            'filter_colour' => 10,  // INCREASED: Allow up to 10 colors
            'filter_color' => 10,   // INCREASED: Allow up to 10 colors  
            'filter_size' => 10,    // INCREASED: Allow up to 10 sizes
            'filter_brand' => 5     // INCREASED: Allow up to 5 brands
        );
        
        foreach ($filter_limits as $filter => $max_values) {
            if (isset($query_params[$filter])) {
                $values = explode(',', $query_params[$filter]);
                
                // Block ONLY if exceeds very high limits
                if (count($values) > $max_values) {
                    $this->log_spam_attempt($url, "Too many values in {$filter}: " . count($values) . " (max: {$max_values})");
                    return true;
                }
                
                // For color filters, check for OBVIOUS spam only
                if (in_array($filter, array('filter_colour', 'filter_color'))) {
                    foreach ($values as $value) {
                        $value = trim(strtolower($value));
                        
                        // Check for obvious spam patterns
                        foreach ($obvious_spam_patterns as $spam_pattern) {
                            if (strpos($value, $spam_pattern) !== false) {
                                $this->log_spam_attempt($url, "Obvious spam pattern in color: {$value}");
                                return true;
                            }
                        }
                        
                        // REMOVED: No longer block based on "unknown" colors
                        // All colors are now considered legitimate unless obviously spam
                    }
                }
            }
        }

        // 4. Check query string length (INCREASED to 500 chars)
        if (strlen($parsed_url['query']) > 500) {
            $this->log_spam_attempt($url, "Query string too long: " . strlen($parsed_url['query']) . " chars (max: 500)");
            return true;
        }

        // 5. Check total query parameters (INCREASED to 15)
        if (count($query_params) > 15) {
            $this->log_spam_attempt($url, "Too many query parameters: " . count($query_params) . " (max: 15)");
            return true;
        }

        // 6. Check total filter count across all parameters (INCREASED to 25)
        $total_filters = 0;
        foreach ($filter_limits as $filter => $limit) {
            if (isset($query_params[$filter])) {
                $values = explode(',', $query_params[$filter]);
                $total_filters += count($values);
            }
        }

        if ($total_filters > 25) {
            $this->log_spam_attempt($url, "Too many total filters: {$total_filters} (max: 25)");
            return true;
        }

        // 7. Block specific known spam parameters (NOT colors)
        $known_spam_parameters = array(
            'srsltid=', // Google spam parameter
            'sessionid=', // Session hijacking attempts
            'userid=', // User ID manipulation
            'admin=', // Admin access attempts
            'debug=', // Debug mode attempts
            'test=123', // Test parameters
            'hack=', // Obvious hacking attempts
        );
        
        foreach ($known_spam_parameters as $pattern) {
            if (strpos($decoded_query, $pattern) !== false) {
                $this->log_spam_attempt($url, "Known spam parameter detected: {$pattern}");
                return true;
            }
        }

        // If we reach here, it's a legitimate URL with real colors
        return false;
    }

    private function log_spam_attempt($url, $reason) {
        // Log spam attempts for analysis
        $log_entry = array(
            'url' => $url,
            'reason' => $reason,
            'timestamp' => current_time('mysql'),
            'ip' => $this->get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        );
        
        $spam_logs = get_option('security_spam_url_logs', array());
        $spam_logs[] = $log_entry;
        
        // Keep only last 200 entries
        if (count($spam_logs) > 200) {
            $spam_logs = array_slice($spam_logs, -200);
        }
        
        update_option('security_spam_url_logs', $spam_logs);
    }

    private function get_client_ip() {
        $ip_keys = array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function has_excessive_query_params($url) {
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['query'])) {
            return false;
        }

        parse_str($parsed_url['query'], $query_params);
        
        // INCREASED: Check total number of query parameters (from 10 to 15)
        if (count($query_params) > 15) {
            $this->log_spam_attempt($url, "Too many query parameters: " . count($query_params) . " (max: 15)");
            return true;
        }

        return false;
    }

    private function is_manual_410_url($url) {
        $manual_410_urls = get_option('security_manual_410_urls', array());
        $path = parse_url($url, PHP_URL_PATH);
        
        return in_array($path, $manual_410_urls) || in_array($url, $manual_410_urls);
    }

    public function handle_410_responses() {
        global $wp_query;

        // Handle 410 for deleted posts
        if (is_404()) {
            $current_url = $_SERVER['REQUEST_URI'];
            $deleted_urls = get_option('security_deleted_post_urls', array());
            
            if (in_array($current_url, $deleted_urls)) {
                $this->send_410_response('Content permanently removed');
            }
        }

        // Handle posts marked as 410
        if (is_single() || is_page()) {
            global $post;
            if ($post && get_post_meta($post->ID, '_send_410_response', true)) {
                $this->send_410_response('Content permanently removed');
            }
        }
    }

    public function store_deleted_post_url($post_id) {
        $post = get_post($post_id);
        if (!$post) {
            return;
        }

        $post_url = parse_url(get_permalink($post_id), PHP_URL_PATH);
        $deleted_urls = get_option('security_deleted_post_urls', array());
        
        if (!in_array($post_url, $deleted_urls)) {
            $deleted_urls[] = $post_url;
            // Keep only last 1000 deleted URLs to prevent database bloat
            if (count($deleted_urls) > 1000) {
                $deleted_urls = array_slice($deleted_urls, -1000);
            }
            update_option('security_deleted_post_urls', $deleted_urls);
        }
    }

    public function add_410_meta_box_hooks() {
        add_action('add_meta_boxes', array($this, 'add_410_meta_box'));
    }

    public function add_410_meta_box() {
        $post_types = get_post_types(array('public' => true));
        foreach ($post_types as $post_type) {
            add_meta_box(
                'seo_410_response',
                '410 Response Settings',
                array($this, 'render_410_meta_box'),
                $post_type,
                'side',
                'default'
            );
        }
    }

    public function render_410_meta_box($post) {
        wp_nonce_field('seo_410_meta_box', 'seo_410_nonce');
        $send_410 = get_post_meta($post->ID, '_send_410_response', true);
        ?>
        <p>
            <label>
                <input type="checkbox" name="send_410_response" value="1" <?php checked($send_410); ?>>
                Send 410 (Gone) response for this content
            </label>
        </p>
        <p class="description">
            When enabled, this page will return a 410 "Gone" status instead of displaying content. 
            This tells search engines the content has been permanently removed.
        </p>
        <?php
    }

    public function save_410_meta_box($post_id) {
        if (!isset($_POST['seo_410_nonce']) || !wp_verify_nonce($_POST['seo_410_nonce'], 'seo_410_meta_box')) {
            return;
        }

        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return;
        }

        if (!current_user_can('edit_post', $post_id)) {
            return;
        }

        if (isset($_POST['send_410_response'])) {
            update_post_meta($post_id, '_send_410_response', 1);
        } else {
            delete_post_meta($post_id, '_send_410_response');
        }
    }

    public function add_410_bulk_action($bulk_actions) {
        $bulk_actions['mark_410'] = 'Mark as 410 (Gone)';
        $bulk_actions['unmark_410'] = 'Remove 410 Status';
        return $bulk_actions;
    }

    public function handle_410_bulk_action($redirect_to, $doaction, $post_ids) {
        if ($doaction === 'mark_410') {
            foreach ($post_ids as $post_id) {
                update_post_meta($post_id, '_send_410_response', 1);
            }
            $redirect_to = add_query_arg('marked_410', count($post_ids), $redirect_to);
        } elseif ($doaction === 'unmark_410') {
            foreach ($post_ids as $post_id) {
                delete_post_meta($post_id, '_send_410_response');
            }
            $redirect_to = add_query_arg('unmarked_410', count($post_ids), $redirect_to);
        }
        
        return $redirect_to;
    }

    public function add_spam_logs_menu() {
        add_submenu_page(
            'security-settings',
            'Spam URL Logs',
            'Spam Logs',
            'manage_options',
            'security-spam-logs',
            array($this, 'render_spam_logs_page')
        );
    }

    public function render_spam_logs_page() {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        // Handle clear logs action
        if (isset($_POST['clear_logs']) && check_admin_referer('clear_spam_logs', 'spam_logs_nonce')) {
            $this->clear_spam_logs();
            echo '<div class="notice notice-success"><p>Spam logs cleared successfully.</p></div>';
        }

        $spam_logs = $this->get_spam_logs();
        ?>
        <div class="wrap">
            <h1>Spam URL Logs</h1>
            <p>This page shows URLs that have been blocked with 410 (Gone) responses due to spam detection.</p>
            
            <form method="post" style="margin-bottom: 20px;">
                <?php wp_nonce_field('clear_spam_logs', 'spam_logs_nonce'); ?>
                <input type="submit" name="clear_logs" class="button" value="Clear All Logs" 
                       onclick="return confirm('Are you sure you want to clear all spam logs?');">
            </form>

            <?php if (empty($spam_logs)): ?>
                <div class="notice notice-info">
                    <p>No spam URLs have been detected yet.</p>
                </div>
            <?php else: ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>URL</th>
                            <th>Reason</th>
                            <th>IP Address</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_reverse($spam_logs) as $log): ?>
                            <tr>
                                <td><?php echo esc_html($log['timestamp']); ?></td>
                                <td style="word-break: break-all; max-width: 300px;">
                                    <code><?php echo esc_html($log['url']); ?></code>
                                </td>
                                <td><?php echo esc_html($log['reason']); ?></td>
                                <td><?php echo esc_html($log['ip']); ?></td>
                                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                                    <?php echo esc_html(substr($log['user_agent'], 0, 100)); ?>
                                    <?php if (strlen($log['user_agent']) > 100): ?>...<?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <p><strong>Total spam URLs blocked:</strong> <?php echo count($spam_logs); ?></p>
            <?php endif; ?>
        </div>
        <?php
    }

    private function send_410_response($message = 'Gone') {
        // FIXED: Redirect to secure cached 410 endpoint instead of direct response
        $secure_410_url = home_url('/security-410/');
        
        // Log the blocked request
        $this->log_spam_attempt($_SERVER['REQUEST_URI'], $message);
        
        // Redirect to secure 410 page
        wp_redirect($secure_410_url, 301);
        exit;
    }

    public function clean_url_for_seo($url) {
        // Only run WooCommerce-specific cleaning if WooCommerce is active
        if (!$this->is_woocommerce_active()) {
            return $url;
        }

        // Remove excessive parameters while keeping essential ones
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['query'])) {
            return $url;
        }

        parse_str($parsed_url['query'], $query_params);
        
        // Keep only essential WooCommerce parameters with reasonable limits
        $essential_params = array(
            'filter_colour' => 10, // INCREASED: Max 10 colors
            'filter_color' => 10,  // INCREASED: Max 10 colors (alternative spelling)
            'filter_size' => 10,   // INCREASED: Max 10 sizes
            'orderby' => true,
            'order' => true,
            'paged' => true,
            'per_page' => true,
            'in-stock' => true,
            'on-sale' => true,
            'on-backorder' => true,
            'featured' => true,
            'query_type_colour' => true, // Allow query_type parameters for legitimate filters
            'query_type_color' => true,
            'query_type_size' => true
        );

        // Add WooCommerce parameters only if WooCommerce is active
        if ($this->is_woocommerce_active()) {
            $woocommerce_params = array(
                'orderby', 'order', 'per_page', 'product_cat', 'product_tag',
                'min_price', 'max_price', 'rating_filter'
            );
            $essential_params = array_merge($essential_params, $woocommerce_params);
        }

        $cleaned_params = array();
        foreach ($essential_params as $param => $limit) {
            if (isset($query_params[$param])) {
                if (is_numeric($limit)) {
                    // Limit multiple values
                    $values = explode(',', $query_params[$param]);
                    $cleaned_params[$param] = implode(',', array_slice($values, 0, $limit));
                } else {
                    $cleaned_params[$param] = $query_params[$param];
                }
            }
        }

        if (empty($cleaned_params)) {
            return $parsed_url['path'];
        }

        return $parsed_url['path'] . '?' . http_build_query($cleaned_params);
    }

    // Admin method to manually add URLs to 410 list
    public function add_manual_410_url($url) {
        if (!current_user_can('manage_options')) {
            return false;
        }
        
        $manual_410_urls = get_option('security_manual_410_urls', array());
        $path = parse_url($url, PHP_URL_PATH);
        
        if (!in_array($path, $manual_410_urls)) {
            $manual_410_urls[] = $path;
            update_option('security_manual_410_urls', $manual_410_urls);
            return true;
        }
        
        return false;
    }

    // Get spam logs for admin review
    public function get_spam_logs() {
        return get_option('security_spam_url_logs', array());
    }

    // Clear spam logs
    public function clear_spam_logs() {
        if (current_user_can('manage_options')) {
            delete_option('security_spam_url_logs');
            // Clear 410 page cache when logs are cleared
            delete_transient('security_410_page_cache_v2');
            return true;
        }
        return false;
    }
    
    // FIXED: Add method to clear 410 page cache
    public function clear_410_cache() {
        delete_transient('security_410_page_cache_v2');
    }
}