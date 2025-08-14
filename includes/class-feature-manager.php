<?php
// includes/class-feature-manager.php

if (!defined('ABSPATH')) {
    exit;
}

class FeatureManager {
    private $excluded_paths_cache = null;
    private static $is_admin = null;
    private static $is_logged_in = null;
    private static $current_user_can_manage = null;
    private $options_cache = array();
    
    private function get_option($key, $default = false) {
        if (!isset($this->options_cache[$key])) {
            $this->options_cache[$key] = get_option($key, $default);
        }
        return $this->options_cache[$key];
    }

    public function init() {
        // Initialize static checks once for performance
        if (self::$is_admin === null) {
            self::$is_admin = is_admin();
        }
        
        if (self::$is_logged_in === null) {
            self::$is_logged_in = is_user_logged_in();
        }
        
        if (self::$current_user_can_manage === null) {
            self::$current_user_can_manage = current_user_can('manage_options');
        }

        // Only load features if needed
        if (!self::$is_admin && !self::$current_user_can_manage) {
            $this->manage_url_security();
            $this->manage_php_access();
            
            // Query string filtering
            if (
                $this->get_option('security_remove_query_strings', false) ||
                $this->get_option('security_enforce_allowed_query_strings', false)
            ) {
                add_action('template_redirect', array($this, 'filter_query_strings'), 0);
            }

            // 410 redirect for 404 pages
            if ($this->get_option('security_enable_410_redirect', false)) {
                add_action('template_redirect', array($this, 'handle_410_redirect'), 1);
            }

            // WooCommerce canonical URLs
            if ($this->is_woocommerce_active()) {
                add_action('wp_head', array($this, 'add_canonical_for_filtered_pages'), 1);
            }
        }

        // Always load these features
        $this->manage_feeds();
        $this->manage_oembed();
        $this->manage_pingback();
        $this->manage_wp_json();
        $this->manage_rsd();
        $this->manage_wp_generator();
    }

    public function handle_410_redirect() {
        // Only handle 404 pages
        if (!is_404()) {
            return;
        }

        // Get excluded URLs
        $excluded_urls_raw = $this->get_option('security_410_excluded_urls', '');
        $excluded_urls = array_filter(array_map('trim', explode("\n", $excluded_urls_raw)));

        $current_path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

        // Check if current path should be excluded
        foreach ($excluded_urls as $excluded) {
            if (!empty($excluded) && stripos($current_path, $excluded) !== false) {
                return; // Allow normal 404 handling
            }
        }

        // Set 410 status
        status_header(410);
        nocache_headers();
        
        // Add additional headers for better SEO
        if (!headers_sent()) {
            header('HTTP/1.1 410 Gone');
            header('Status: 410 Gone');
            header('X-Robots-Tag: noindex, nofollow');
        }

        // Try to load the custom 410 template
        $template_loaded = false;
        
        // First, try to load the 410-page.php template from your plugin
        $plugin_template = plugin_dir_path(__FILE__) . '../templates/410-page.php';
        if (file_exists($plugin_template)) {
            include($plugin_template);
            $template_loaded = true;
        }
        
        // If plugin template not found, try to get the security-410 page
        if (!$template_loaded) {
            $page = get_page_by_path('security-410');
            if ($page && $page->post_status === 'publish') {
                // Set up global post data
                global $post;
                $post = $page;
                setup_postdata($post);
                
                // Get the theme's page template or use default
                $page_template = get_page_template();
                if ($page_template && file_exists($page_template)) {
                    include($page_template);
                    $template_loaded = true;
                } else {
                    // Fallback to content only
                    echo apply_filters('the_content', $page->post_content);
                    $template_loaded = true;
                }
                
                wp_reset_postdata();
            }
        }
        
        // Final fallback if nothing else worked
        if (!$template_loaded) {
            echo '<h1>410 Gone</h1><p>This content is no longer available.</p>';
        }
        
        exit;
    }

    private function is_woocommerce_active() {
        return class_exists('WooCommerce') && function_exists('is_shop');
    }

    public function add_canonical_for_filtered_pages() {
        // Double-check WooCommerce is available
        if (!$this->is_woocommerce_active()) {
            return;
        }

        // Check if we're on a WooCommerce page
        if (!is_shop() && !is_product_category() && !is_product_tag()) {
            return;
        }

        $current_url = $_SERVER['REQUEST_URI'];
        $parsed_url = parse_url($current_url);
        
        if (isset($parsed_url['query'])) {
            parse_str($parsed_url['query'], $query_params);
            
            // If there are filter parameters, set canonical to the clean URL
            $filter_params = array('filter_colour', 'filter_size', 'filter_brand', 'filter_price');
            $has_filters = false;
            
            foreach ($filter_params as $param) {
                if (isset($query_params[$param])) {
                    $has_filters = true;
                    break;
                }
            }
            
            if ($has_filters) {
                $canonical_url = home_url($parsed_url['path']);
                echo '<link rel="canonical" href="' . esc_url($canonical_url) . '" />' . "\n";
                echo '<meta name="robots" content="noindex, follow" />' . "\n";
            }
        }
    }

    public function remove_query_strings() {
        // CRITICAL: Skip for logged-in users and admins
        if (self::$is_admin || self::$is_logged_in || self::$current_user_can_manage || empty($_SERVER['QUERY_STRING'])) {
            return;
        }

        $request_uri = $_SERVER['REQUEST_URI'];
        $path = parse_url($request_uri, PHP_URL_PATH);
        $query = parse_url($request_uri, PHP_URL_QUERY);
        
        if (empty($query)) {
            return;
        }

        parse_str($query, $query_params);

        // Enhanced WordPress core parameters
        $wordpress_core_params = array(
            'preview', 'p', 'page_id', 'post_type', 'preview_id', 'preview_nonce',
            'tb', 'replytocom', 'unapproved', 'moderation-hash', 's', 'paged',
            'cat', 'tag', 'author', 'year', 'monthnum', 'day', 'feed',
            'withcomments', 'withoutcomments', 'attachment_id', 'subpage', 'static',
            'customize_theme', 'customize_changeset_uuid', 'customize_autosaved',
            'wp_customize', 'doing_wp_cron', 'rest_route', 'wc-ajax',
            'add-to-cart', 'remove_item', 'undo_item', 'update_cart', 'proceed',
            'elementor-preview', 'ver', 'v', '_wpnonce', 'action', 'redirect_to',
            'loggedout', 'registration', 'checkemail', 'key', 'login', 'interim-login',
            'customize_messenger_channel', 'fl_builder', 'et_fb', 'ct_builder',
            'tve', 'vcv-action', 'vc_action', 'brizy-edit', 'brizy-edit-iframe'
        );

        // Add WooCommerce parameters only if WooCommerce is active
        if ($this->is_woocommerce_active()) {
            $woocommerce_params = array(
                'orderby', 'order', 'per_page', 'product_cat', 'product_tag',
                'min_price', 'max_price', 'rating_filter'
            );
            $wordpress_core_params = array_merge($wordpress_core_params, $woocommerce_params);
        }

        // Check WordPress core parameters
        foreach ($wordpress_core_params as $core_param) {
            if (isset($query_params[$core_param])) {
                return;
            }
        }

        // Check allowed WooCommerce filters with limits (only if WooCommerce is active)
        if ($this->is_woocommerce_active()) {
            $allowed_wc_filters = array(
                'filter_colour' => 2, // Max 2 colors
                'filter_size' => 3,   // Max 3 sizes
                'in-stock' => true
            );

            $allowed_filters = 0;
            foreach ($allowed_wc_filters as $filter => $limit) {
                if (isset($query_params[$filter])) {
                    if (is_numeric($limit)) {
                        $values = explode(',', $query_params[$filter]);
                        if (count($values) <= $limit) {
                            $allowed_filters++;
                        } else {
                            // Too many values, redirect to clean URL
                            wp_redirect($path, 301);
                            exit;
                        }
                    } else {
                        $allowed_filters++;
                    }
                }
            }

            // If we have allowed filters, keep them
            if ($allowed_filters > 0) {
                return;
            }
        }

        // Check excluded paths
        foreach ($this->get_excluded_paths() as $excluded) {
            if (empty($excluded)) {
                continue;
            }

            if (strpos($excluded, '?') === 0) {
                $param = trim($excluded, '?=');
                if (isset($query_params[$param])) {
                    return;
                }
            } else {
                $excluded_parts = parse_url($excluded);
                $excluded_path = isset($excluded_parts['path']) ? trim($excluded_parts['path'], '/') : '';
                $excluded_query = isset($excluded_parts['query']) ? $excluded_parts['query'] : '';
                
                $current_path = trim($path, '/');
                
                if ($current_path === $excluded_path && $query === $excluded_query) {
                    return;
                }
                
                if ($current_path === $excluded_path && empty($excluded_query)) {
                    return;
                }
            }
        }

        // Redirect to clean URL
        if ($path !== $request_uri) {
            wp_redirect($path, 301);
            exit;
        }
    }
    
    public function filter_query_strings() {
        if (is_admin()) return;

        $remove_enabled = $this->get_option('security_remove_query_strings', false);
        $allowed_enabled = $this->get_option('security_enforce_allowed_query_strings', false);

        $allowed_params = [];
        if ($allowed_enabled) {
            $list = $this->get_option('security_allowed_query_strings', '');
            $allowed_params = array_filter(array_map('trim', explode(',', $list)));
        }

        $current_params = $_GET;
        $filtered_params = [];

        foreach ($current_params as $key => $value) {
            // Keep only if allowed list contains it
            if ($allowed_enabled && !in_array($key, $allowed_params, true)) {
                continue;
            }

            // Or if removal is disabled, keep everything
            if (!$remove_enabled || ($allowed_enabled && in_array($key, $allowed_params, true))) {
                $filtered_params[$key] = $value;
            }
        }

        // Redirect if query strings changed
        if ($current_params !== $filtered_params) {
            $base_url = strtok($_SERVER["REQUEST_URI"], '?');
            if (!empty($filtered_params)) {
                $base_url .= '?' . http_build_query($filtered_params);
            }
            wp_redirect(home_url($base_url), 301);
            exit;
        }
    }

    private function manage_feeds() {
        if ($this->get_option('security_remove_feeds', false)) {
            remove_action('wp_head', 'feed_links', 2);
            remove_action('wp_head', 'feed_links_extra', 3);
            add_action('do_feed', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rdf', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rss', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rss2', array($this, 'disable_feeds'), 1);
            add_action('do_feed_atom', array($this, 'disable_feeds'), 1);
        }
    }

    public function disable_feeds() {
        status_header(410);
        wp_die(__('RSS Feeds have been permanently disabled.', 'security-plugin'));
    }

    private function manage_oembed() {
        if ($this->get_option('security_remove_oembed', false)) {
            remove_action('wp_head', 'wp_oembed_add_discovery_links');
            remove_action('wp_head', 'wp_oembed_add_host_js');
            remove_filter('oembed_dataparse', 'wp_filter_oembed_result', 10);
            remove_action('rest_api_init', 'wp_oembed_register_route');
            add_filter('embed_oembed_discover', '__return_false');
        }
    }

    private function manage_pingback() {
        if ($this->get_option('security_remove_pingback', false)) {
            remove_action('wp_head', 'pingback_link');
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', array($this, 'remove_pingback_header'));
            add_filter('xmlrpc_methods', array($this, 'remove_xmlrpc_methods'));
        }
    }

    public function remove_pingback_header($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    public function remove_xmlrpc_methods($methods) {
        unset($methods['pingback.ping']);
        unset($methods['pingback.extensions.getPingbacks']);
        return $methods;
    }

    private function manage_wp_json() {
        if ($this->get_option('security_remove_wp_json', false)) {
            remove_action('wp_head', 'rest_output_link_wp_head');
            remove_action('template_redirect', 'rest_output_link_header', 11);
            remove_action('xmlrpc_rsd_apis', 'rest_output_rsd');
            add_filter('rest_enabled', '__return_false');
            add_filter('rest_jsonp_enabled', '__return_false');
        }
    }

    private function manage_rsd() {
        if ($this->get_option('security_remove_rsd', false)) {
            remove_action('wp_head', 'rsd_link');
        }
    }

    private function manage_wp_generator() {
        if ($this->get_option('security_remove_wp_generator', false)) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
        }
    }

    private function manage_php_access() {
        if (!self::$is_admin && !self::$current_user_can_manage) {
            add_action('init', array($this, 'block_direct_php_access'));
        }
    }

    public function block_direct_php_access() {
        $request_uri = $_SERVER['REQUEST_URI'];
        
        if (preg_match('/\.php$/i', $request_uri)) {
            $current_path = trim($request_uri, '/');
            $excluded_php_paths = explode("\n", $this->get_option('security_excluded_php_paths', ''));
            
            foreach ($excluded_php_paths as $excluded_path) {
                $excluded_path = trim($excluded_path, '/');
                if (!empty($excluded_path) && strpos($current_path, $excluded_path) === 0) {
                    return;
                }
            }
            
            $this->send_403_response();
        }
    }

    private function manage_url_security() {
        if (!self::$is_admin && !self::$current_user_can_manage) {
            add_action('init', array($this, 'check_url_security'));
        }
    }

    public function check_url_security() {
        $current_url = $_SERVER['REQUEST_URI'];
        
        // Check excluded paths
        foreach ($this->get_excluded_paths() as $path) {
            if (!empty($path) && strpos($current_url, $path) !== false) {
                return;
            }
        }

        // Check blocked patterns
        foreach ($this->get_blocked_patterns() as $pattern) {
            if (!empty($pattern) && strpos($current_url, $pattern) !== false) {
                $this->send_403_response('Security Error: Blocked Pattern Detected');
            }
        }
    }

    private function send_403_response($message = '403 Forbidden') {
        status_header(403);
        nocache_headers();
        header('HTTP/1.1 403 Forbidden');
        header('Status: 403 Forbidden');
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
        }
        die($message);
    }

    private function get_excluded_paths() {
        if ($this->excluded_paths_cache === null) {
            $paths = $this->get_option('security_excluded_paths', '');
            if (empty($paths)) {
                $this->excluded_paths_cache = array();
                return array();
            }

            $this->excluded_paths_cache = array_filter(
                array_map(
                    'trim',
                    explode("\n", $paths)
                )
            );
        }
        return $this->excluded_paths_cache;
    }

    public function get_blocked_patterns() {
        return array_filter(array_map('trim', explode("\n", $this->get_option('security_blocked_patterns', ''))));
    }
    
    public function enforce_allowed_query_strings() {
        if (self::$is_admin || self::$is_logged_in || self::$current_user_can_manage) {
            return;
        }

        $allowed_list = $this->get_option('security_allowed_query_strings', '');
        $allowed_params = array_filter(array_map('trim', explode(',', $allowed_list)));

        if (empty($allowed_params)) {
            return; // No restriction if no list is set
        }

        $current_params = $_GET;
        $filtered_params = [];

        foreach ($current_params as $key => $value) {
            if (in_array($key, $allowed_params, true)) {
                $filtered_params[$key] = $value;
            }
        }

        if ($current_params !== $filtered_params) {
            $base_url = strtok($_SERVER["REQUEST_URI"], '?');
            if (!empty($filtered_params)) {
                $base_url .= '?' . http_build_query($filtered_params);
            }
            wp_redirect(home_url($base_url), 301);
            exit;
        }
    }
}