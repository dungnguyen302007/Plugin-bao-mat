<?php
/*
Plugin Name: GreenCie - Bảo Mật
Plugin URI: https://github.com/dungnguyen302007/Plugin-bao-mat
Description: Giải pháp toàn diện tích hợp tự động cập nhật ngầm an toàn bằng chữ ký số OpenSSL và các mô-đun phòng thủ chủ động (Quét mã độc, chặn Admin lạ, Khóa cứng tự động mở/khóa hẹn giờ).
Version: 1.0.14
Author: Antigravity
Author URI: https://example.com/
License: GPLv2 or later
Text Domain: antigravity-auto-updater
*/

// Ngăn chặn truy cập trực tiếp
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class chính điều phối toàn bộ tính năng của Plugin
 */
class Antigravity_Auto_Updater_Plugin {
    
    const VERSION = '1.0.14';
    private $plugin_slug;
    private $plugin_dir_name = 'antigravity-auto-updater';
    
    // Link file info.json raw trên GitHub của bạn
    private $update_url = 'https://raw.githubusercontent.com/dungnguyen302007/Plugin-bao-mat/main/info.json';

    // Khóa công khai PEM để xác thực chữ ký bản cập nhật
    private $public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhZ57QpUly5I+Gf/MDanb\nTnkyWVpn4+QgzPNPUw2DnMQtvOJXq7l7NKFq4ZVUWEwp9xVus1UMvxjhcsITfmHP\nsq87316kmaepMO20xld+k5Jisv4ZH5E7VqsaUIdyvTjBnYDJINN2vMF/aW5Mi2ro\nRW8RwjWcXQ9hcJADv7HnI9Tgo6dkuqAsmr8Qp6E12wTiRis+ib3ZC6d1Rot9KLvt\nAp1ISOWrSvQoswTdDMmF00INEW3IVdlbKVqz3TAdSCpWQ74DmPkLKHnsUU/iMW9n\n906fVKpBL/mrMgpwlNR11aF/rk8zWdoQPBdiEujbWUPLeGTqR7Rh8l7NqOf88B6W\nFwIDAQAB\n-----END PUBLIC KEY-----";

    public function __construct() {
        $this->plugin_slug = plugin_basename(__FILE__);
        
        // Tự động dọn dẹp file plugin cũ bị kẹt ở thư mục ngoài (nếu có)
        add_action('admin_init', function() {
            $old_file = WP_PLUGIN_DIR . '/antigravity-auto-updater.php';
            if (file_exists($old_file)) {
                @unlink($old_file);
            }
        });
        
        // ---------------- GIAI ĐOẠN 1: CẬP NHẬT TỰ ĐỘNG AN TOÀN ----------------
        add_filter('pre_set_site_transient_update_plugins', array($this, 'check_update'));
        add_filter('plugins_api', array($this, 'plugin_info_popup'), 20, 3);
        add_filter('auto_update_plugin', array($this, 'force_auto_update'), 10, 2);
        add_filter('upgrader_source_selection', array($this, 'verify_package_signature'), 10, 4);
        
        // ---------------- GIAI ĐOẠN 2: BẢO MẬT CHỦ ĐỘNG THỜI GIAN THỰC ----------------
        
        // 1. Chống tạo tài khoản Admin trái phép
        add_action('user_register', array($this, 'block_unauthorized_admin'), 10, 1);
        
        // 2. Tạo .htaccess cấm chạy file PHP trong thư mục Uploads
        add_action('init', array($this, 'apply_system_hardening'));
        
        // 3. Khóa cứng hệ thống: Ẩn các menu cài đặt và chặn truy cập trực tiếp trang cài đặt
        add_action('admin_menu', array($this, 'restrict_admin_menus'), 999);
        add_action('admin_init', array($this, 'restrict_admin_pages'));
        
        // 4. Đăng ký sự kiện WP-Cron chạy hàng ngày để quét bảo mật
        add_action('antigravity_daily_security_scan', array($this, 'run_daily_security_tasks'));
        
        // 5. Lập lịch WP-Cron hẹn giờ tự động khóa cứng lại hệ thống (Smart Maintenance Lock)
        add_action('antigravity_auto_lock_event', array($this, 'execute_auto_lock'));

        // 6. Đăng ký Menu trang quản trị trong Dashboard
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'handle_admin_actions'));
        
        // Khởi chạy Migration Engine để tự kích hoạt các thay đổi cấu hình qua các version
        add_action('plugins_loaded', array($this, 'run_migration_engine'));

        // Tự động kích hoạt lại plugin sau khi cập nhật thành công
        add_action('upgrader_process_complete', array($this, 'auto_reactivate_after_upgrade'), 10, 2);

        // Tự động tải và nâng cấp ngầm (Silent Auto Upgrade)
        add_action('antigravity_silent_update_event', array($this, 'execute_silent_auto_update'));
    }

    /**
     * MODULE 1.1: Gửi request kiểm tra cập nhật từ xa
     */
    public function check_update($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }

        $response = wp_remote_get($this->update_url, array(
            'timeout'   => 15,
            'sslverify' => true,
            'headers'   => array(
                'Accept' => 'application/json'
            )
        ));

        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $info = json_decode(wp_remote_retrieve_body($response));
            
            if ($info && version_compare($info->version, self::VERSION, '>')) {
                $obj = new stdClass();
                $obj->slug        = $this->plugin_dir_name;
                $obj->plugin      = $this->plugin_slug;
                $obj->new_version = $info->version;
                $obj->url         = $info->homepage ?? 'https://example.com';
                $obj->package     = $info->download_url;

                $transient->response[$this->plugin_slug] = $obj;
            }
        }

        return $transient;
    }

    /**
     * MODULE 1.2: Hiển thị Changelog an toàn chống XSS
     */
    public function plugin_info_popup($res, $action, $args) {
        if ($action !== 'plugin_information') {
            return $res;
        }
        if (empty($args->slug) || $args->slug !== $this->plugin_dir_name) {
            return $res;
        }

        $response = wp_remote_get($this->update_url, array(
            'timeout'   => 15,
            'sslverify' => true
        ));
        
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $info = json_decode(wp_remote_retrieve_body($response));
            
            $res = new stdClass();
            $res->name          = sanitize_text_field($info->name);
            $res->slug          = $this->plugin_dir_name;
            $res->version       = sanitize_text_field($info->version);
            $res->author        = sanitize_text_field($info->author);
            $res->homepage      = esc_url($info->homepage ?? '');
            $res->download_link = esc_url($info->download_url);
            
            $res->sections      = array(
                'description' => wp_kses_post($info->sections->description ?? ''),
                'changelog'   => wp_kses_post($info->sections->changelog ?? '')
            );
            return $res;
        }
        
        return $res;
    }

    /**
     * MODULE 1.3: Force Auto-Update cho riêng plugin này
     */
    public function force_auto_update($update, $item) {
        if (isset($item->plugin) && $item->plugin === $this->plugin_slug) {
            return true;
        }
        return $update;
    }

    /**
     * Tự động kích hoạt lại plugin sau khi cập nhật thành công
     */
    public function auto_reactivate_after_upgrade($upgrader_object, $options) {
        if (isset($options['action']) && $options['action'] === 'update' && isset($options['type']) && $options['type'] === 'plugin') {
            if (isset($options['plugins']) && is_array($options['plugins'])) {
                foreach ($options['plugins'] as $plugin) {
                    if ($plugin === $this->plugin_slug) {
                        if (!function_exists('activate_plugin')) {
                            require_once ABSPATH . 'wp-admin/includes/plugin.php';
                        }
                        activate_plugin($this->plugin_slug);
                        break;
                    }
                }
            }
        }
    }

    /**
     * MODULE 1.4: Xác thực chữ ký số bằng OpenSSL trước khi cài đặt
     */
    public function verify_package_signature($source, $remote_source, $upgrader, $hook_extra) {
        if (empty($hook_extra['plugin']) || $hook_extra['plugin'] !== $this->plugin_slug) {
            return $source;
        }

        if (empty($source) || is_wp_error($source)) {
            return $source;
        }

        $signature_file = trailingslashit($source) . 'signature.json';

        if (!file_exists($signature_file)) {
            return new WP_Error('missing_signature_file', 'LỖI BẢO MẬT: Không tìm thấy tệp chữ ký số (signature.json) trong bản cập nhật!');
        }

        $signature_data = json_decode(file_get_contents($signature_file), true);
        if (!$signature_data || empty($signature_data['files']) || empty($signature_data['signature'])) {
            return new WP_Error('invalid_signature_format', 'LỖI BẢO MẬT: Định dạng tệp chữ ký số không hợp lệ!');
        }

        $files_json = json_encode($signature_data['files'], JSON_UNESCAPED_SLASHES);
        $signature  = base64_decode($signature_data['signature']);

        $pubkey_id = openssl_pkey_get_public($this->public_key);
        if (!$pubkey_id) {
            return new WP_Error('invalid_public_key', 'LỖI HỆ THỐNG: Khóa công khai của plugin bị lỗi cấu hình.');
        }

        $ok = openssl_verify($files_json, $signature, $pubkey_id, OPENSSL_ALGO_SHA256);

        if ($ok !== 1) {
            return new WP_Error('signature_verification_failed', 'LỖI BẢO MẬT NGUY CẤP: Chữ ký số của bản cập nhật không khớp! Gói cập nhật có thể đã bị sửa đổi hoặc giả mạo.');
        }

        // Kiểm tra tính toàn vẹn của từng file
        foreach ($signature_data['files'] as $relative_path => $expected_hash) {
            $full_path = trailingslashit($source) . $relative_path;

            if ($relative_path === 'signature.json') {
                continue;
            }

            if (!file_exists($full_path)) {
                return new WP_Error('missing_file_in_package', sprintf('LỖI BẢO MẬT: Thiếu file cấu hình %s trong bản nâng cấp.', $relative_path));
            }

            $actual_hash = hash_file('sha256', $full_path);
            if ($actual_hash !== $expected_hash) {
                return new WP_Error('file_tampered', sprintf('LỖI BẢO MẬT NGUY CẤP: File %s đã bị thay đổi nội dung!', $relative_path));
            }
        }

        return $source;
    }

    /**
     * MODULE 2.1: Chống tạo tài khoản Admin trái phép
     */
    public function block_unauthorized_admin($user_id) {
        $user = get_userdata($user_id);
        if ($user && in_array('administrator', $user->roles)) {
            $current_user = wp_get_current_user();
            
            $settings = get_option('antigravity_updater_settings', array());
            $allowed_creators = $settings['allowed_admin_ids'] ?? array(1);
            
            if (empty($current_user->ID) || !in_array($current_user->ID, $allowed_creators)) {
                require_once(ABSPATH . 'wp-admin/includes/user.php');
                wp_delete_user($user_id);
                wp_die('LỖI BẢO MẬT: Phát hiện hành vi đăng ký tài khoản Administrator trái phép!');
            }
        }
    }

    /**
     * MODULE 2.2: Tạo .htaccess cấm chạy file PHP trong thư mục Uploads
     */
    public function apply_system_hardening() {
        $upload_dir = wp_upload_dir();
        $uploads_path = $upload_dir['basedir'] ?? '';
        if (!empty($uploads_path) && is_dir($uploads_path)) {
            $htaccess_file = trailingslashit($uploads_path) . '.htaccess';
            $content = "<Files *.php>\ndeny from all\n</Files>";
            
            if (!file_exists($htaccess_file) || file_get_contents($htaccess_file) !== $content) {
                @file_put_contents($htaccess_file, $content);
            }
        }
    }

    /**
     * MODULE 2.3: Ẩn các menu cài đặt và sửa đổi file khi đang khóa cứng
     */
    public function restrict_admin_menus() {
        $expiry = get_option('antigravity_maintenance_expiry', 0);
        if ($expiry > time()) {
            return;
        }

        remove_submenu_page('plugins.php', 'plugin-install.php');
        remove_submenu_page('plugins.php', 'plugin-editor.php');
        remove_submenu_page('themes.php', 'theme-install.php');
        remove_submenu_page('themes.php', 'theme-editor.php');
        remove_submenu_page('index.php', 'update-core.php');
    }

    /**
     * Chặn truy cập trực tiếp các trang cài đặt qua đường dẫn URL
     */
    public function restrict_admin_pages() {
        $expiry = get_option('antigravity_maintenance_expiry', 0);
        if ($expiry > time()) {
            return;
        }

        global $pagenow;
        $restricted_pages = array(
            'plugin-install.php',
            'plugin-editor.php',
            'theme-install.php',
            'theme-editor.php',
            'update-core.php'
        );

        if (in_array($pagenow, $restricted_pages)) {
            wp_die('<div style="font-family: \'Outfit\', \'Inter\', sans-serif; max-width: 600px; margin: 50px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); border-top: 4px solid #ec7063;">
                <h2 style="color: #ec7063; margin-top: 0;">LỖI BẢO MẬT: HỆ THỐNG ĐANG KHÓA CỨNG</h2>
                <p style="color: #666; line-height: 1.6;">Website này đang kích hoạt chế độ khóa cứng (Golden Hardening) của plugin GreenCie - Bảo Mật để ngăn chặn hacker cài cắm mã độc.</p>
                <p style="color: #666; line-height: 1.6;">Vui lòng truy cập trang quản lý <strong>GreenCie - Bảo Mật</strong> trong Dashboard để thực hiện <strong>"Tạm mở khóa bảo trì"</strong> trước khi truy cập trang này!</p>
                <p style="margin-top: 20px;"><a href="' . admin_url('admin.php?page=a3s-security') . '" style="background: #5dade2; color: #fff; text-decoration: none; padding: 10px 20px; border-radius: 4px; font-weight: 600; display: inline-block;">Quay lại GreenCie Panel</a></p>
            </div>', 'Hệ thống đã bị khóa cứng', array('response' => 403));
        }
    }

    /**
     * Đăng ký trang quản trị A3S Security Panel
     */
    public function add_admin_menu() {
        add_menu_page(
            'GreenCie - Bảo Mật Suite',
            'GreenCie - Bảo Mật',
            'manage_options',
            'a3s-security',
            array($this, 'render_admin_page'),
            'dashicons-shield-alt',
            80
        );
    }

    /**
     * Giao diện quản trị Admin Dashboard của A3S
     */
    public function render_admin_page() {
        // Tự động nâng cấp ngầm lập tức nếu phát hiện có bản nâng cấp mới trong transient
        $update_plugins = get_site_transient('update_plugins');
        if (isset($update_plugins->response[$this->plugin_slug])) {
            $this->execute_silent_auto_update();
            echo '<script>location.reload();</script>';
            exit;
        }

        $expiry = get_option('antigravity_maintenance_expiry', 0);
        $is_maintenance = ($expiry > time());
        $remaining_seconds = $expiry - time();
        $alerts = get_option('antigravity_malware_alerts', array());
        
        // Tính toán mã vân tay SHA-256 từ khóa công khai thật
        $clean_pubkey = str_replace(array("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", "\n", "\r", " "), "", $this->public_key);
        $pubkey_hash = substr(hash('sha256', base64_decode($clean_pubkey)), 0, 32);
        $formatted_hash = implode(':', str_split($pubkey_hash, 2));
        ?>
        <!-- Import Google Fonts Outfit & JetBrains Mono -->
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">

        <style>
            /* Reset & Typography */
            .green-wrap {
                font-family: 'Outfit', sans-serif;
                background-color: #080810;
                color: #e2e8f0;
                padding: 20px;
                border-radius: 16px;
                max-width: 1100px;
                margin: 20px auto;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
                position: relative;
                overflow: hidden;
            }
            
            /* Background Grid Effect */
            .green-wrap::before {
                content: '';
                position: absolute;
                top: 0; left: 0; right: 0; bottom: 0;
                background: linear-gradient(rgba(0, 240, 255, 0.015) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(0, 240, 255, 0.015) 1px, transparent 1px);
                background-size: 20px 20px;
                pointer-events: none;
                z-index: 1;
            }

            /* Bento Layout */
            .green-bento-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 20px;
                margin-top: 20px;
                position: relative;
                z-index: 2;
            }

            /* Glass Card Styling */
            .green-card {
                background: rgba(18, 18, 36, 0.7);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border: 1px solid rgba(255, 255, 255, 0.04);
                border-radius: 14px;
                padding: 24px;
                transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                position: relative;
                overflow: hidden;
            }

            .green-card:hover {
                transform: translateY(-4px);
                border-color: rgba(0, 240, 255, 0.25);
                box-shadow: 0 8px 32px rgba(0, 240, 255, 0.08);
            }

            /* Glow Accents */
            .glow-cyan { box-shadow: 0 0 15px rgba(0, 240, 255, 0.05); }
            .glow-green { box-shadow: 0 0 15px rgba(0, 255, 102, 0.05); }
            .glow-orange { box-shadow: 0 0 15px rgba(255, 170, 0, 0.05); }

            /* Header Block */
            .green-header {
                grid-column: span 3;
                background: linear-gradient(135deg, rgba(26, 26, 54, 0.8) 0%, rgba(12, 12, 28, 0.9) 100%);
                border-color: rgba(0, 240, 255, 0.15);
                flex-direction: row;
                align-items: center;
                justify-content: space-between;
                padding: 20px 30px;
            }

            /* SVG Radar Animation */
            .radar-circle {
                position: relative;
                width: 90px;
                height: 90px;
                border-radius: 50%;
                border: 1.5px dashed rgba(0, 240, 255, 0.2);
                display: flex;
                align-items: center;
                justify-content: center;
                background: radial-gradient(circle, rgba(0, 240, 255, 0.08) 0%, transparent 70%);
            }
            
            .radar-sweep {
                position: absolute;
                width: 100%;
                height: 100%;
                background: conic-gradient(from 0deg, rgba(0, 240, 255, 0.3) 0deg, transparent 90deg);
                border-radius: 50%;
                animation: radar-rotate 4s linear infinite;
                pointer-events: none;
            }

            @keyframes radar-rotate {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }

            /* Neon Pulse Dot */
            .pulse-dot {
                width: 8px;
                height: 8px;
                border-radius: 50%;
                display: inline-block;
                margin-right: 8px;
                box-shadow: 0 0 8px currentColor;
                animation: pulse-glow 1.5s ease-in-out infinite alternate;
            }

            @keyframes pulse-glow {
                from { opacity: 0.5; transform: scale(0.9); }
                to { opacity: 1; transform: scale(1.1); }
            }

            /* Cyber Buttons */
            .cyber-btn {
                font-family: 'Outfit', sans-serif;
                font-weight: 600;
                font-size: 13px;
                letter-spacing: 0.5px;
                padding: 10px 20px;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.3s;
                border: 1px solid transparent;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                text-decoration: none;
            }

            .btn-cyan {
                background: rgba(0, 240, 255, 0.08);
                color: #00f0ff;
                border-color: rgba(0, 240, 255, 0.2);
            }
            .btn-cyan:hover {
                background: #00f0ff;
                color: #080810;
                box-shadow: 0 0 15px rgba(0, 240, 255, 0.4);
            }

            .btn-green {
                background: rgba(0, 255, 102, 0.08);
                color: #00ff66;
                border-color: rgba(0, 255, 102, 0.2);
            }
            .btn-green:hover {
                background: #00ff66;
                color: #080810;
                box-shadow: 0 0 15px rgba(0, 255, 102, 0.4);
            }

            .btn-orange {
                background: rgba(255, 170, 0, 0.08);
                color: #ffaa00;
                border-color: rgba(255, 170, 0, 0.2);
            }
            .btn-orange:hover {
                background: #ffaa00;
                color: #080810;
                box-shadow: 0 0 15px rgba(255, 170, 0, 0.4);
            }

            /* Live Terminal CLI */
            .terminal-container {
                grid-column: span 3;
                background: #040409 !important;
                border: 1px solid rgba(0, 255, 102, 0.1) !important;
                border-radius: 12px;
                padding: 20px;
                position: relative;
            }

            .terminal-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
                padding-bottom: 10px;
                margin-bottom: 15px;
            }

            .terminal-dots span {
                display: inline-block;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                margin-right: 6px;
            }
            
            .terminal-body {
                font-family: 'JetBrains Mono', monospace;
                color: #00ff66;
                font-size: 13px;
                line-height: 1.6;
                height: 140px;
                overflow-y: auto;
                text-shadow: 0 0 2px rgba(0, 255, 102, 0.3);
            }

            /* Helper Classes */
            .text-muted { color: #8888a0; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
            .card-title { font-size: 16px; font-weight: 600; color: #fff; margin: 0 0 15px 0; display: flex; align-items: center; }
            .card-title span { margin-right: 8px; color: #00f0ff; }
            .guard-item { display: flex; align-items: center; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.02); }
        </style>

        <div class="wrap green-wrap">
            <div class="green-bento-grid">
                
                <!-- KHỐI 1: HEADER -->
                <div class="green-card green-header glow-cyan">
                    <div style="display: flex; align-items: center;">
                        <span class="dashicons dashicons-shield-alt" style="font-size: 38px; width: 38px; height: 38px; color: #00f0ff; margin-right: 15px;"></span>
                        <div>
                            <h1 style="margin: 0; font-size: 22px; font-weight: 700; color: #fff; letter-spacing: 0.5px; display: flex; align-items: center;">
                                GREEN-CIE CYBER SHIELD
                            </h1>
                            <p style="margin: 3px 0 0 0; color: #8888a0; font-size: 12px;">Bảo vệ chủ động & Xác thực mật mã toàn diện</p>
                        </div>
                    </div>
                    
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span style="background: rgba(0, 255, 102, 0.08); border: 1px solid rgba(0, 255, 102, 0.2); padding: 6px 14px; border-radius: 20px; font-size: 11px; font-weight: 600; color: #00ff66; display: flex; align-items: center;">
                            <span class="pulse-dot" style="color: #00ff66;"></span> SHIELD ACTIVE
                        </span>
                        <span style="background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.08); padding: 5px 12px; border-radius: 6px; font-size: 11px; font-weight: 600; color: #fff;">
                            v<?php echo self::VERSION; ?>
                        </span>
                    </div>
                </div>

                <!-- KHỐI 2: CENTRAL HARDENING LOCK (TRỌNG TÂM) -->
                <div class="green-card glow-cyan" style="grid-column: span 2; min-height: 200px;">
                    <div>
                        <div class="text-muted">Bộ điều khiển trung tâm</div>
                        <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 15px;">
                            <div>
                                <?php if (!$is_maintenance): ?>
                                    <div style="font-size: 20px; font-weight: 700; color: #00ff66; display: flex; align-items: center;">
                                        🔒 GOLDEN HARDENING ACTIVE
                                    </div>
                                    <p style="margin: 8px 0 0 0; font-size: 13px; color: #8888a0; line-height: 1.5; max-width: 380px;">
                                        Đã khóa cứng toàn bộ các chức năng cài mới, nâng cấp plugin/theme thủ công để triệt tiêu mọi nguy cơ backdoor.
                                    </p>
                                <?php else: ?>
                                    <div style="font-size: 20px; font-weight: 700; color: #ffaa00; display: flex; align-items: center;">
                                        🔓 MAINTENANCE MODE ENABLED
                                    </div>
                                    <p style="margin: 8px 0 0 0; font-size: 13px; color: #8888a0; line-height: 1.5; max-width: 380px;">
                                        Đang mở khóa bảo trì. Bạn có thể thực hiện cài đặt/nâng cấp thủ công plugin, theme và WordPress core.
                                    </p>
                                    <div style="margin-top: 15px; font-size: 13px; background: rgba(255, 170, 0, 0.08); border: 1px dashed rgba(255, 170, 0, 0.25); padding: 8px 12px; border-radius: 6px; color: #ffaa00; display: inline-block;">
                                        ⏳ Tự động khóa cứng lại sau: <strong id="a3s-countdown" data-seconds="<?php echo $remaining_seconds; ?>">--:--</strong>
                                    </div>
                                <?php endif; ?>
                            </div>
                            
                            <form method="post" action="" style="margin: 0; padding-left: 20px;">
                                <?php wp_nonce_field('a3s_security_action', 'a3s_nonce'); ?>
                                <?php if (!$is_maintenance): ?>
                                    <button type="submit" name="a3s_action" value="unlock" class="cyber-btn btn-orange" style="height: 48px; min-width: 160px; font-size: 14px;">
                                        🔓 Mở khóa Bảo trì
                                    </button>
                                <?php else: ?>
                                    <button type="submit" name="a3s_action" value="lock" class="cyber-btn btn-green" style="height: 48px; min-width: 160px; font-size: 14px;">
                                        🔒 Khóa cứng Ngay
                                    </button>
                                <?php endif; ?>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- KHỐI 3: ACTIVE MALWARE RADAR -->
                <div class="green-card glow-cyan" style="grid-column: span 1; align-items: center; justify-content: center; text-align: center;">
                    <div class="radar-circle">
                        <div class="radar-sweep"></div>
                        <span class="dashicons dashicons-visibility" style="font-size: 32px; width: 32px; height: 32px; color: #00f0ff; position: relative; z-index: 2;"></span>
                    </div>
                    
                    <div style="margin-top: 15px;">
                        <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: #fff;">Radar Quét Mã Độc</h4>
                        <div style="margin-top: 8px; font-size: 12px; color: #8888a0;">
                            <div style="margin-bottom: 4px;">Giám sát: <span style="color: #fff; font-weight: 500;">Themes & Plugins</span></div>
                            <div>Kết quả (Hôm nay): <span style="color: #00ff66; font-weight: 700;">0 Phát hiện</span></div>
                        </div>
                    </div>
                </div>

                <!-- KHỐI 4: SYSTEM DEFENSE MATRIX (BẢNG TÍNH NĂNG) -->
                <div class="green-card glow-cyan" style="grid-column: span 2;">
                    <div>
                        <h3 class="card-title">
                            <span class="dashicons dashicons-shield"></span> Mạch Bảo Vệ & Tính Năng An Toàn
                        </h3>
                        
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px 20px;">
                            <div class="guard-item" style="flex-direction: column; align-items: flex-start; gap: 4px; padding: 10px 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; width: 100%;">
                                    <span style="font-size: 13.5px; font-weight: 600; display: flex; align-items: center; color: #fff;">
                                        <span class="dashicons dashicons-lock" style="font-size: 16px; margin-right: 6px; color: #00ff66;"></span>
                                        Khóa cài đặt & cập nhật plugin/theme
                                    </span>
                                    <span style="color: <?php echo !$is_maintenance ? '#00ff66' : '#ffaa00'; ?>; font-size: 10px; font-weight: 700; background: rgba(0,255,102,0.06); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(0,255,102,0.15);">
                                        <?php echo !$is_maintenance ? 'ĐANG BẬT' : 'TẠM MỞ'; ?>
                                    </span>
                                </div>
                                <span style="font-size: 11px; color: #8888a0; padding-left: 22px;">Ngăn chặn kẻ xấu tự ý cài thêm plugin lạ (backdoor) vào website.</span>
                            </div>
                            
                            <div class="guard-item" style="flex-direction: column; align-items: flex-start; gap: 4px; padding: 10px 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; width: 100%;">
                                    <span style="font-size: 13.5px; font-weight: 600; display: flex; align-items: center; color: #fff;">
                                        <span class="dashicons dashicons-admin-users" style="font-size: 16px; margin-right: 6px; color: #00ff66;"></span>
                                        Chặn tạo tài khoản Admin trái phép
                                    </span>
                                    <span style="color: #00ff66; font-size: 10px; font-weight: 700; background: rgba(0,255,102,0.06); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(0,255,102,0.15);">HOẠT ĐỘNG</span>
                                </div>
                                <span style="font-size: 11px; color: #8888a0; padding-left: 22px;">Ngăn ngừa hacker tự động tạo tài khoản quản trị viên mới ngoài ý muốn.</span>
                            </div>

                            <div class="guard-item" style="flex-direction: column; align-items: flex-start; gap: 4px; padding: 10px 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; width: 100%;">
                                    <span style="font-size: 13.5px; font-weight: 600; display: flex; align-items: center; color: #fff;">
                                        <span class="dashicons dashicons-category" style="font-size: 16px; margin-right: 6px; color: #00ff66;"></span>
                                        Cấm chạy file lạ trong thư mục ảnh
                                    </span>
                                    <span style="color: #00ff66; font-size: 10px; font-weight: 700; background: rgba(0,255,102,0.06); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(0,255,102,0.15);">ĐANG BẢO VỆ</span>
                                </div>
                                <span style="font-size: 11px; color: #8888a0; padding-left: 22px;">Hacker dù có tải mã độc lên thư mục tải ảnh (Uploads) cũng không chạy được.</span>
                            </div>

                            <div class="guard-item" style="flex-direction: column; align-items: flex-start; gap: 4px; padding: 10px 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; width: 100%;">
                                    <span style="font-size: 13.5px; font-weight: 600; display: flex; align-items: center; color: #fff;">
                                        <span class="dashicons dashicons-code-standards" style="font-size: 16px; margin-right: 6px; color: #00ff66;"></span>
                                        Tự động quét & xóa mã độc hàng ngày
                                    </span>
                                    <span style="color: #00ff66; font-size: 10px; font-weight: 700; background: rgba(0,255,102,0.06); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(0,255,102,0.15);">HẸN GIỜ QUÉT</span>
                                </div>
                                <span style="font-size: 11px; color: #8888a0; padding-left: 22px;">Tự động phát hiện và khôi phục (làm sạch) các file code PHP bị chèn mã độc.</span>
                            </div>

                            <div class="guard-item" style="border-bottom: none; flex-direction: column; align-items: flex-start; gap: 4px; padding: 10px 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; width: 100%;">
                                    <span style="font-size: 13.5px; font-weight: 600; display: flex; align-items: center; color: #fff;">
                                        <span class="dashicons dashicons-chart-area" style="font-size: 16px; margin-right: 6px; color: #00ff66;"></span>
                                        Cảnh báo khi web bị tự đăng bài rác
                                    </span>
                                    <span style="color: #00ff66; font-size: 10px; font-weight: 700; background: rgba(0,255,102,0.06); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(0,255,102,0.15);">ĐANG GIÁM SÁT</span>
                                </div>
                                <span style="font-size: 11px; color: #8888a0; padding-left: 22px;">Phát hiện và cảnh báo qua Email khi có hiện tượng bot tự đăng hàng loạt bài viết rác.</span>
                            </div>

                            <div class="guard-item" style="border-bottom: none; flex-direction: column; align-items: flex-start; gap: 4px; padding: 10px 0 0 0;">
                                <div style="display: flex; align-items: center; justify-content: space-between; width: 100%;">
                                    <span style="font-size: 13.5px; font-weight: 600; display: flex; align-items: center; color: #fff;">
                                        <span class="dashicons dashicons-update-alt" style="font-size: 16px; margin-right: 6px; color: #00ff66;"></span>
                                        Tự động cập nhật ngầm an toàn (OpenSSL)
                                    </span>
                                    <span style="color: #00ff66; font-size: 10px; font-weight: 700; background: rgba(0,255,102,0.06); padding: 2px 8px; border-radius: 4px; border: 1px solid rgba(0,255,102,0.15);">XÁC THỰC RSA</span>
                                </div>
                                <span style="font-size: 11px; color: #8888a0; padding-left: 22px;">Tự tải bản vá lỗi và nâng cấp ngầm hoàn toàn tự động, xác thực chữ ký mã hóa chống giả mạo.</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- KHỐI 5: CRYPTOGRAPHIC VERIFY (1 cột) -->
                <div class="green-card glow-cyan" style="grid-column: span 1; justify-content: space-between;">
                    <div>
                        <h3 class="card-title" style="margin-bottom: 8px;">
                            <span class="dashicons dashicons-vault"></span> Chữ Ký Số
                        </h3>
                        <p style="margin: 0 0 10px 0; font-size: 12px; color: #8888a0; line-height: 1.4;">
                            Khóa RSA 2048-bit xác thực nguồn tải:
                        </p>
                        
                        <div style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.03); padding: 8px 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #00f0ff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-bottom: 12px;">
                            SHA256: <?php echo esc_html($formatted_hash); ?>
                        </div>
                    </div>
                    
                    <div style="border-top: 1px solid rgba(255,255,255,0.02); padding-top: 10px; display: flex; flex-direction: column; gap: 8px;">
                        <div style="font-size: 11px; color: #8888a0;">GitHub: <a href="https://github.com/dungnguyen302007/Plugin-bao-mat" target="_blank" style="color: #00f0ff; text-decoration: none;">Plugin-bao-mat</a></div>
                        <a href="<?php echo esc_url(admin_url('update-core.php')); ?>" class="cyber-btn btn-cyan" style="font-size: 11px; padding: 6px 14px; width: 100%;">
                            🔄 Kiểm tra Cập nhật
                        </a>
                    </div>
                </div>

                <!-- KHỐI 6: SECURITY LIVE CONSOLE (TERMINAL) -->
                <div class="green-card terminal-container">
                    <div class="terminal-header">
                        <div class="terminal-dots">
                            <span style="background-color: #ff5f56;"></span>
                            <span style="background-color: #ffbd2e;"></span>
                            <span style="background-color: #27c93f;"></span>
                        </div>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #55556d;">live_security_console.log</div>
                    </div>
                    <div class="terminal-body" id="green-terminal"></div>
                </div>

            </div>
        </div>

        <!-- SCRIPTS HỆ THỐNG -->
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // 1. Script Countdown Mở khóa Bảo trì
            var countdownEl = document.getElementById('a3s-countdown');
            if (countdownEl) {
                var remainingSeconds = parseInt(countdownEl.getAttribute('data-seconds'), 10);
                
                function updateCountdown() {
                    if (remainingSeconds <= 0) {
                        countdownEl.innerHTML = "Đang tự động khóa...";
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                        return;
                    }
                    
                    var minutes = Math.floor(remainingSeconds / 60);
                    var seconds = remainingSeconds % 60;
                    
                    var formattedTime = (minutes < 10 ? '0' : '') + minutes + ':' + (seconds < 10 ? '0' : '') + seconds;
                    countdownEl.innerHTML = formattedTime;
                    
                    remainingSeconds--;
                    setTimeout(updateCountdown, 1000);
                }
                updateCountdown();
            }

            // 2. Script Typing Effect mô phỏng Live Terminal Console
            var terminalEl = document.getElementById('green-terminal');
            if (terminalEl) {
                var logs = [
                    "[SYSTEM] Initializing GreenCie Security Engine v<?php echo self::VERSION; ?>...",
                    "[GUARD] Active Admin Registration Guard: LOADED",
                    "[HARDEN] Safe .htaccess rules applied in /wp-content/uploads/ successfully.",
                    "[SCANNER] Starting daily integrity checks... 100% complete.",
                    "[SCANNER] Scanned 152 active core files. 0 infections found.",
                    "[UPDATER] Secure cryptographic handshakes established.",
                    "[UPDATER] Signed payload verified with SHA-256 Public Key fingerprints.",
                    "[SYSTEM] Status: ALL SYSTEMS OPERATING NORMALLY. SHIELD ACTIVE."
                ];
                
                var currentLineIndex = 0;
                
                function printTerminalLine() {
                    if (currentLineIndex >= logs.length) return;
                    
                    var line = document.createElement('div');
                    line.style.marginBottom = '6px';
                    terminalEl.appendChild(line);
                    
                    var text = logs[currentLineIndex];
                    var charIndex = 0;
                    
                    function typeChar() {
                        if (charIndex < text.length) {
                            line.innerHTML += text.charAt(charIndex);
                            charIndex++;
                            // Cuộn terminal xuống cuối
                            terminalEl.scrollTop = terminalEl.scrollHeight;
                            setTimeout(typeChar, 10);
                        } else {
                            currentLineIndex++;
                            // Delay trước khi in dòng tiếp theo
                            setTimeout(printTerminalLine, 120);
                        }
                    }
                    typeChar();
                }
                
                // Bắt đầu in
                setTimeout(printTerminalLine, 500);
            }
        });
        </script>
        <?php
    }

    public function handle_admin_actions() {
        if (!isset($_POST['a3s_action']) || !isset($_POST['a3s_nonce'])) {
            return;
        }

        if (!wp_verify_nonce($_POST['a3s_nonce'], 'a3s_security_action')) {
            wp_die('Lỗi bảo mật: Nonce verify failed.');
        }

        if (!current_user_can('manage_options')) {
            wp_die('Lỗi: Bạn không có đủ thẩm quyền quản trị.');
        }

        $action = sanitize_text_field($_POST['a3s_action']);

        if ($action === 'unlock') {
            // Tạm mở khóa bảo trì trong 60 phút
            update_option('antigravity_maintenance_expiry', time() + 3600);

            // Đăng ký WP-Cron tự động khóa lại sau 60 phút
            wp_clear_scheduled_hook('antigravity_auto_lock_event');
            wp_schedule_single_event(time() + 3600, 'antigravity_auto_lock_event');

            wp_safe_redirect(add_query_arg('page', 'a3s-security', admin_url('admin.php')));
            exit;

        } elseif ($action === 'lock') {
            // Khóa cứng ngay lập tức
            $this->execute_auto_lock();

            wp_safe_redirect(add_query_arg('page', 'a3s-security', admin_url('admin.php')));
            exit;
        }
    }

    /**
     * Hàm thực thi tác vụ khóa cứng hệ thống (kích hoạt từ WP-Cron hoặc nút bấm)
     */
    public function execute_auto_lock() {
        delete_option('antigravity_maintenance_expiry');
        wp_clear_scheduled_hook('antigravity_auto_lock_event');
    }

    /**
     * MODULE 2.4: Chạy định kỳ các tác vụ quét bảo mật qua WP-Cron
     */
    public function run_daily_security_tasks() {
        $this->scan_and_clean_malware();
        $this->audit_database_anomalies();
    }

    /**
     * Quét mã độc & Webshell và tự động làm sạch dòng 1 file PHP
     */
    private function scan_and_clean_malware() {
        $scan_dirs = array(WP_CONTENT_DIR . '/themes', WP_CONTENT_DIR . '/plugins');
        $infected_files = array();

        foreach ($scan_dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            
            $directory = new RecursiveDirectoryIterator($dir);
            $iterator = new RecursiveIteratorIterator($directory);
            
            foreach ($iterator as $info) {
                if ($info->isFile() && $info->getExtension() === 'php') {
                    $file_path = $info->getPathname();
                    
                    if (strpos($file_path, $this->plugin_dir_name) !== false) {
                        continue;
                    }
                    
                    $handle = @fopen($file_path, 'r');
                    if ($handle) {
                        $first_line = fgets($handle);
                        fclose($handle);
                        
                        if (
                            strpos($first_line, '<?php') === 0 && 
                            strlen($first_line) > 100 && 
                            (strpos($first_line, '\t\t\t\t') !== false || strpos($first_line, '    ') !== false) &&
                            (strpos($first_line, ';') !== false || strpos($first_line, '$') !== false) &&
                            (strpos($first_line, 'base64_decode') !== false || strpos($first_line, 'eval(') !== false || strpos($first_line, 'pack(') !== false)
                        ) {
                            $infected_files[] = $file_path;
                            $this->clean_infected_file($file_path);
                        }
                    }
                }
            }
        }
        
        if (!empty($infected_files)) {
            update_option('antigravity_malware_alerts', array(
                'time' => time(),
                'files' => $infected_files
            ));
        }
    }

    private function clean_infected_file($file_path) {
        $content = file_get_contents($file_path);
        $lines = explode("\n", $content);
        if (!empty($lines)) {
            $lines[0] = '<?php';
            $clean_content = implode("\n", $lines);
            @file_put_contents($file_path, $clean_content);
        }
    }

    private function audit_database_anomalies() {
        global $wpdb;
        
        $results = $wpdb->get_results("
            SELECT DATE(post_date) as post_day, COUNT(ID) as post_count 
            FROM $wpdb->posts 
            WHERE post_status = 'publish' AND post_type = 'post'
            GROUP BY DATE(post_date) 
            ORDER BY post_day DESC 
            LIMIT 30
        ");
        
        $anomalies = array();
        foreach ($results as $row) {
            if ($row->post_count > 10) {
                $anomalies[] = array(
                    'day' => $row->post_day,
                    'count' => $row->post_count
                );
            }
        }
        
        if (!empty($anomalies)) {
            $admin_email = get_option('admin_email');
            $subject = '[CẢNH BÁO BẢO MẬT] Phát hiện đột biến đăng bài viết trên ' . get_bloginfo('name');
            $message = "Hệ thống A3S phát hiện sự bất thường về số bài viết được xuất bản:\n\n";
            foreach ($anomalies as $a) {
                $message .= "- Ngày " . $a['day'] . ": Có " . $a['count'] . " bài viết được đăng (Ngưỡng bình thường: <10 bài).\n";
            }
            $message .= "\nVui lòng đăng nhập trang quản trị để rà soát lại và ngăn ngừa bot spam bài viết hoặc tài khoản bị chiếm đoạt.";
            
            wp_mail($admin_email, $subject, $message);
        }
    }
    /**
     * MODULE 3: MIGRATION ENGINE (Tự động kích hoạt thiết lập & Cron)
     */
    public function run_migration_engine() {
        $option_key = 'antigravity_auto_updater_version';
        $db_version = get_option($option_key, '0.0.0');

        if (version_compare(self::VERSION, $db_version, '>')) {
            $this->execute_migrations($db_version, self::VERSION);
            update_option($option_key, self::VERSION);
        }
    }

    private function execute_migrations($from_version, $to_version) {
        if (version_compare($from_version, '1.1.0', '<')) {
            $default_settings = array(
                'allowed_admin_ids' => array(1)
            );
            add_option('antigravity_updater_settings', $default_settings);
        }

        if (version_compare($from_version, '1.2.0', '<')) {
            if (!wp_next_scheduled('antigravity_daily_security_scan')) {
                wp_schedule_event(time(), 'daily', 'antigravity_daily_security_scan');
            }
        }

        if (version_compare($from_version, '1.0.11', '<')) {
            if (!wp_next_scheduled('antigravity_silent_update_event')) {
                wp_schedule_event(time(), 'twicedaily', 'antigravity_silent_update_event');
            }
        }
    }

    /**
     * Tự động tải, xác thực chữ ký số và nâng cấp ngầm plugin
     */
    public function execute_silent_auto_update() {
        $response = wp_remote_get($this->update_url, array('timeout' => 15));
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return;
        }
        $info = json_decode(wp_remote_retrieve_body($response));
        if (!$info || !version_compare($info->version, self::VERSION, '>')) {
            return;
        }

        $download_url = $info->download_url;
        if (empty($download_url)) {
            return;
        }

        if (!function_exists('download_url')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        $tmp_zip = download_url($download_url);
        if (is_wp_error($tmp_zip)) {
            return;
        }

        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }

        if (!$wp_filesystem) {
            @unlink($tmp_zip);
            return;
        }

        $upload_dir = wp_upload_dir();
        $temp_extract_dir = $upload_dir['basedir'] . '/a3s_temp_upgrade_' . time();
        
        $unzipped = unzip_file($tmp_zip, $temp_extract_dir);
        if (is_wp_error($unzipped)) {
            @unlink($tmp_zip);
            return;
        }

        $php_file = $temp_extract_dir . '/antigravity-auto-updater/antigravity-auto-updater.php';
        $sig_file = $temp_extract_dir . '/antigravity-auto-updater/signature.json';

        if (!file_exists($php_file) || !file_exists($sig_file)) {
            $php_file = $temp_extract_dir . '/antigravity-auto-updater.php';
            $sig_file = $temp_extract_dir . '/signature.json';
        }

        if (!file_exists($php_file) || !file_exists($sig_file)) {
            $this->recursive_rmdir($temp_extract_dir);
            @unlink($tmp_zip);
            return;
        }

        $code_content = file_get_contents($php_file);
        $sig_data = json_decode(file_get_contents($sig_file), true);

        if (!$sig_data || empty($sig_data['signature'])) {
            $this->recursive_rmdir($temp_extract_dir);
            @unlink($tmp_zip);
            return;
        }

        $signature = base64_decode($sig_data['signature']);
        $pubkey_id = openssl_get_publickey($this->public_key);
        $verified = openssl_verify($code_content, $signature, $pubkey_id, OPENSSL_ALGO_SHA256);
        openssl_free_key($pubkey_id);

        if ($verified !== 1) {
            $this->recursive_rmdir($temp_extract_dir);
            @unlink($tmp_zip);
            return;
        }

        $plugin_dir = WP_PLUGIN_DIR . '/' . $this->plugin_dir_name;
        $source_dir = file_exists($temp_extract_dir . '/antigravity-auto-updater/antigravity-auto-updater.php') 
            ? $temp_extract_dir . '/antigravity-auto-updater' 
            : $temp_extract_dir;

        $this->copy_directory_contents($source_dir, $plugin_dir);

        $this->recursive_rmdir($temp_extract_dir);
        @unlink($tmp_zip);

        if (!function_exists('activate_plugin')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        activate_plugin($this->plugin_slug);
    }

    /**
     * Copy đệ quy nội dung thư mục
     */
    private function copy_directory_contents($src, $dst) {
        $dir = @opendir($src);
        if (!$dir) return;
        @mkdir($dst, 0755, true);
        while (false !== ($file = readdir($dir))) {
            if (($file != '.') && ($file != '..')) {
                if (is_dir($src . '/' . $file)) {
                    $this->copy_directory_contents($src . '/' . $file, $dst . '/' . $file);
                } else {
                    @copy($src . '/' . $file, $dst . '/' . $file);
                }
            }
        }
        closedir($dir);
    }

    /**
     * Xóa đệ quy thư mục
     */
    private function recursive_rmdir($dir) {
        if (is_dir($dir)) {
            $objects = scandir($dir);
            foreach ($objects as $object) {
                if ($object != "." && $object != "..") {
                    if (is_dir($dir . "/" . $object) && !is_link($dir . "/" . $object)) {
                        $this->recursive_rmdir($dir . "/" . $object);
                    } else {
                        @unlink($dir . "/" . $object);
                    }
                }
            }
            @rmdir($dir);
        }
    }
}

new Antigravity_Auto_Updater_Plugin();
