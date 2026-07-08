<?php
/*
Plugin Name: Antigravity Auto Updater & Security Suite
Plugin URI: https://github.com/your-username/antigravity-auto-updater
Description: Giải pháp toàn diện tích hợp tự động cập nhật ngầm an toàn từ xa và các mô-đun phòng thủ chủ động (Quét mã độc, chặn Admin lạ, Khóa cứng tự động mở/khóa hẹn giờ).
Version: 1.0.0
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
    
    const VERSION = '1.0.0';
    private $plugin_slug;
    private $plugin_dir_name = 'antigravity-auto-updater';
    
    // ⚠️ HÃY THAY LINK NÀY THÀNH ĐƯỜNG DẪN FILE info.json TRÊN SERVER ONLINE CỦA BẠN
    private $update_url = 'https://raw.githubusercontent.com/your-username/antigravity-auto-updater/main/info.json';

    public function __construct() {
        $this->plugin_slug = plugin_basename(__FILE__);
        
        // ---------------- GIAI ĐOẠN 1: CẬP NHẬT TỰ ĐỘNG NGẦM TỪ XA ----------------
        add_filter('pre_set_site_transient_update_plugins', array($this, 'check_update'));
        add_filter('plugins_api', array($this, 'plugin_info_popup'), 20, 3);
        add_filter('auto_update_plugin', array($this, 'force_auto_update'), 10, 2);
        
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
                <p style="color: #666; line-height: 1.6;">Website này đang kích hoạt chế độ khóa cứng (Golden Hardening) của plugin A3S Security để ngăn chặn hacker cài cắm mã độc.</p>
                <p style="color: #666; line-height: 1.6;">Vui lòng truy cập trang quản lý <strong>A3S Security</strong> trong Dashboard để thực hiện <strong>"Tạm mở khóa bảo trì"</strong> trước khi truy cập trang này!</p>
                <p style="margin-top: 20px;"><a href="' . admin_url('admin.php?page=a3s-security') . '" style="background: #5dade2; color: #fff; text-decoration: none; padding: 10px 20px; border-radius: 4px; font-weight: 600; display: inline-block;">Quay lại A3S Panel</a></p>
            </div>', 'Hệ thống đã bị khóa cứng', array('response' => 403));
        }
    }

    /**
     * Đăng ký trang quản trị A3S Security Panel
     */
    public function add_admin_menu() {
        add_menu_page(
            'A3S Security Suite',
            'A3S Security',
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
        $expiry = get_option('antigravity_maintenance_expiry', 0);
        $is_maintenance = ($expiry > time());
        $remaining_seconds = $expiry - time();
        ?>
        <div class="wrap" style="max-width: 800px; margin: 30px auto; font-family: 'Outfit', 'Inter', sans-serif;">
            <div style="background: linear-gradient(135deg, #1e1e38 0%, #111125 100%); padding: 30px; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.15); color: #fff;">
                
                <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 20px; margin-bottom: 25px;">
                    <div>
                        <h1 style="margin: 0; font-size: 24px; font-weight: 700; color: #5dade2; display: flex; align-items: center;">
                            <span class="dashicons dashicons-shield-alt" style="font-size: 32px; width: 32px; height: 32px; margin-right: 10px; color: #5dade2;"></span>
                            Antigravity A3S Security Panel
                        </h1>
                        <p style="margin: 5px 0 0 0; color: #a9dfbf; font-size: 13px;">Hệ thống bảo vệ chủ động và Tự động cập nhật an toàn</p>
                    </div>
                    <span style="background: rgba(255,255,255,0.08); padding: 5px 12px; border-radius: 20px; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; color: #ccc;">V<?php echo self::VERSION; ?></span>
                </div>

                <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); padding: 25px; border-radius: 10px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 12px; text-transform: uppercase; color: #888; letter-spacing: 1px; margin-bottom: 5px;">Trạng thái hệ thống file</div>
                        <?php if (!$is_maintenance): ?>
                            <div style="font-size: 20px; font-weight: 700; color: #ec7063; display: flex; align-items: center;">
                                <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #ec7063; margin-right: 8px; box-shadow: 0 0 10px #ec7063;"></span>
                                KHÓA CỨNG (AN TOÀN CAO)
                            </div>
                            <p style="margin: 8px 0 0 0; font-size: 13px; color: #aaa;">Đã ẩn toàn bộ các tính năng cài mới, cập nhật plugin/theme thủ công để phòng ngừa backdoor.</p>
                        <?php else: ?>
                            <div style="font-size: 20px; font-weight: 700; color: #f4d03f; display: flex; align-items: center;">
                                <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #f4d03f; margin-right: 8px; box-shadow: 0 0 10px #f4d03f;"></span>
                                ĐANG MỞ KHÓA BẢO TRÌ
                            </div>
                            <p style="margin: 8px 0 0 0; font-size: 13px; color: #aaa;">Cho phép cài đặt/cập nhật plugin, theme và core WordPress thủ công.</p>
                            <div style="margin-top: 10px; font-size: 14px; background: rgba(244, 208, 63, 0.1); border: 1px dashed rgba(244, 208, 63, 0.3); padding: 8px 12px; border-radius: 5px; color: #f4d03f; display: inline-block;">
                                ⏰ Tự động khóa lại sau: <strong><?php echo ceil($remaining_seconds / 60); ?> phút</strong>
                            </div>
                        <?php endif; ?>
                    </div>

                    <form method="post" action="">
                        <?php wp_nonce_field('a3s_security_action', 'a3s_nonce'); ?>
                        <?php if (!$is_maintenance): ?>
                            <button type="submit" name="a3s_action" value="unlock" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); color: #fff; border: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 4px 15px rgba(230, 126, 34, 0.4);">
                                🔓 Tạm mở khóa (60 phút)
                            </button>
                        <?php else: ?>
                            <button type="submit" name="a3s_action" value="lock" style="background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%); color: #fff; border: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 4px 15px rgba(46, 204, 113, 0.4);">
                                🔒 Khóa cứng hệ thống ngay
                            </button>
                        <?php endif; ?>
                    </form>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div style="background: rgba(255,255,255,0.01); border: 1px solid rgba(255,255,255,0.03); padding: 20px; border-radius: 8px;">
                        <h3 style="margin-top: 0; color: #5dade2; font-size: 15px; display: flex; align-items: center;">
                            <span class="dashicons dashicons-update" style="margin-right: 5px; font-size: 18px; width: 18px; height: 18px;"></span>
                            Cơ chế Tự cập nhật
                        </h3>
                        <p style="color: #bbb; font-size: 12.5px; line-height: 1.6; margin-bottom: 0;">
                            Hệ thống cập nhật tự động ngầm thông minh. Các website của bạn sẽ tự động kiểm tra, tải bản vá và nâng cấp ngầm thông qua WP-Cron mỗi khi bạn ra mắt phiên bản mới trên server.
                        </p>
                    </div>

                    <div style="background: rgba(255,255,255,0.01); border: 1px solid rgba(255,255,255,0.03); padding: 20px; border-radius: 8px;">
                        <h3 style="margin-top: 0; color: #5dade2; font-size: 15px; display: flex; align-items: center;">
                            <span class="dashicons dashicons-admin-users" style="margin-right: 5px; font-size: 18px; width: 18px; height: 18px;"></span>
                            Giám sát Bảo mật Chủ động
                        </h3>
                        <p style="color: #bbb; font-size: 12.5px; line-height: 1.6; margin-bottom: 0;">
                            Ngăn chặn các tài khoản Admin mới đăng ký trái phép, cấm thực thi mã PHP trong thư mục Uploads, tự động quét tìm và cứu hộ file PHP bị hacker ghi đè mã độc dòng 1 hàng ngày.
                        </p>
                    </div>
                </div>

                <?php
                $alerts = get_option('antigravity_malware_alerts', array());
                if (!empty($alerts)):
                ?>
                <div style="margin-top: 25px; background: rgba(236, 112, 99, 0.08); border: 1px solid rgba(236, 112, 99, 0.2); padding: 20px; border-radius: 8px;">
                    <h3 style="margin-top: 0; color: #ec7063; font-size: 15px; display: flex; align-items: center;">
                        <span class="dashicons dashicons-warning" style="margin-right: 5px; font-size: 18px; width: 18px; height: 18px;"></span>
                        Nhật ký cảnh báo mã độc dòng 1 (Gần nhất)
                    </h3>
                    <p style="font-size: 12px; color: #ccc; margin-bottom: 10px;">Đã phát hiện và tự động làm sạch vào ngày: <?php echo date('d-m-Y H:i:s', $alerts['time']); ?></p>
                    <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: #ec7063; font-family: monospace;">
                        <?php foreach ($alerts['files'] as $f): ?>
                            <li><?php echo esc_html($f); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
                <?php endif; ?>

            </div>
        </div>
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
    }
}

new Antigravity_Auto_Updater_Plugin();
