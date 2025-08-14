<?php
// includes/emergency-unblock.php
// Emergency unblock script for real users

if (!defined('ABSPATH')) {
    exit;
}

class EmergencyUnblock {
    public function __construct() {
        // Add emergency unblock endpoint
        add_action('init', array($this, 'handle_emergency_unblock'));
        
        // Add admin notice for emergency unblock
        add_action('admin_notices', array($this, 'show_emergency_unblock_notice'));
    }
    
    public function handle_emergency_unblock() {
        // Check for emergency unblock request
        if (isset($_GET['emergency_unblock']) && isset($_GET['ip'])) {
            $ip = sanitize_text_field($_GET['ip']);
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $this->emergency_unblock_ip($ip);
                
                // Show success message
                wp_die('
                    <h1>Emergency Unblock Successful</h1>
                    <p>IP address <strong>' . esc_html($ip) . '</strong> has been unblocked.</p>
                    <p>The IP has been added to the whitelist to prevent future blocks.</p>
                    <p><a href="' . admin_url('admin.php?page=security-settings') . '">Go to Security Settings</a></p>
                ');
            }
        }
    }
    
    private function emergency_unblock_ip($ip) {
        global $wpdb;
        
        // Unblock from bot protection table
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
        
        // Log the emergency unblock
        error_log("Emergency unblock performed for IP: $ip");
    }
    
    public function show_emergency_unblock_notice() {
        if (current_user_can('manage_options')) {
            ?>
            <div class="notice notice-info">
                <p><strong>🚨 Emergency Unblock:</strong> If a real user is blocked, use this URL format to unblock them:</p>
                <p><code><?php echo home_url('/?emergency_unblock=1&ip=USER_IP_ADDRESS'); ?></code></p>
                <p>Replace <code>USER_IP_ADDRESS</code> with the actual IP address that needs to be unblocked.</p>
            </div>
            <?php
        }
    }
}

// Initialize emergency unblock
new EmergencyUnblock();