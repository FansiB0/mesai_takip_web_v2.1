-- ========================================
-- SYSTEM_LOGS Tablosu Oluşturma
-- MESA Takip Sistemi Detaylı Log Sistemi
-- ========================================

-- system_logs tablosunu oluştur
CREATE TABLE IF NOT EXISTS system_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    level VARCHAR(20) NOT NULL CHECK (level IN ('info', 'warning', 'error', 'success', 'debug')),
    category VARCHAR(20) NOT NULL CHECK (category IN ('auth', 'user', 'salary', 'overtime', 'leave', 'system', 'admin', 'data', 'security', 'performance')),
    message TEXT NOT NULL,
    details JSONB,
    user_id TEXT,
    user_email VARCHAR(255),
    user_action VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    error_code VARCHAR(100),
    error_stack TEXT,
    data_before JSONB,
    data_after JSONB,
    duration INTEGER, -- milisaniye cinsinden
    resource VARCHAR(255), -- hangi kaynak/endpoint
    method VARCHAR(10), -- HTTP method
    status_code INTEGER,
    request_size INTEGER,
    response_size INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performans için index'ler oluştur
CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON system_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level);
CREATE INDEX IF NOT EXISTS idx_system_logs_category ON system_logs(category);
CREATE INDEX IF NOT EXISTS idx_system_logs_user_id ON system_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_system_logs_user_email ON system_logs(user_email);
CREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_logs_level_category ON system_logs(level, category);
CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp_level ON system_logs(timestamp DESC, level);

-- Full-text search için GIN index
CREATE INDEX IF NOT EXISTS idx_system_logs_message_gin ON system_logs USING gin(to_tsvector('turkish', message));
CREATE INDEX IF NOT EXISTS idx_system_logs_details_gin ON system_logs USING gin(details);

-- Row Level Security (RLS) etkinleştir
ALTER TABLE system_logs ENABLE ROW LEVEL SECURITY;

-- RLS Politikaları
-- Sadece admin'ler tüm logları görebilir
CREATE POLICY "Admins can view all logs" ON system_logs
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM auth.users 
            WHERE auth.users.id = auth.uid() 
            AND auth.users.raw_user_meta_data->>'role' = 'admin'
        )
    );

-- Admin'ler log ekleyebilir
CREATE POLICY "Admins can insert logs" ON system_logs
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM auth.users 
            WHERE auth.users.id = auth.uid() 
            AND auth.users.raw_user_meta_data->>'role' = 'admin'
        )
    );

-- Sistem otomatik log ekleyebilir (service rol)
CREATE POLICY "Service can insert logs" ON system_logs
    FOR INSERT WITH CHECK (true);

-- Kullanıcılar sadece kendi loglarını görebilir (opsiyonel)
CREATE POLICY "Users can view their own logs" ON system_logs
    FOR SELECT USING (
        auth.uid()::text = user_id
    );

-- Trigger: updated_at alanını otomatik güncelle
CREATE OR REPLACE FUNCTION update_system_logs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_update_system_logs_updated_at
    BEFORE UPDATE ON system_logs
    FOR EACH ROW
    EXECUTE FUNCTION update_system_logs_updated_at();

-- Log temizleme fonksiyonu (30 günden eski logları temizler)
CREATE OR REPLACE FUNCTION cleanup_old_logs(days_to_keep INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM system_logs 
    WHERE created_at < NOW() - INTERVAL '1 day' * days_to_keep;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Log temizleme işlemini de logla
    INSERT INTO system_logs (level, category, message, details)
    VALUES ('info', 'system', 'Eski loglar temizlendi', 
            json_build_object('deleted_count', deleted_count, 'days_kept', days_to_keep));
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Log istatistikleri fonksiyonu
CREATE OR REPLACE FUNCTION get_log_statistics(
    start_date TIMESTAMP WITH TIME ZONE DEFAULT NOW() - INTERVAL '30 days',
    end_date TIMESTAMP WITH TIME ZONE DEFAULT NOW()
)
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'total_logs', COUNT(*),
        'by_level', json_build_object(
            'info', COUNT(*) FILTER (WHERE level = 'info'),
            'warning', COUNT(*) FILTER (WHERE level = 'warning'),
            'error', COUNT(*) FILTER (WHERE level = 'error'),
            'success', COUNT(*) FILTER (WHERE level = 'success'),
            'debug', COUNT(*) FILTER (WHERE level = 'debug')
        ),
        'by_category', json_build_object(
            'auth', COUNT(*) FILTER (WHERE category = 'auth'),
            'user', COUNT(*) FILTER (WHERE category = 'user'),
            'salary', COUNT(*) FILTER (WHERE category = 'salary'),
            'overtime', COUNT(*) FILTER (WHERE category = 'overtime'),
            'leave', COUNT(*) FILTER (WHERE category = 'leave'),
            'system', COUNT(*) FILTER (WHERE category = 'system'),
            'admin', COUNT(*) FILTER (WHERE category = 'admin'),
            'data', COUNT(*) FILTER (WHERE category = 'data'),
            'security', COUNT(*) FILTER (WHERE category = 'security'),
            'performance', COUNT(*) FILTER (WHERE category = 'performance')
        ),
        'recent_errors', COUNT(*) FILTER (WHERE level = 'error' AND created_at > NOW() - INTERVAL '24 hours'),
        'average_duration', ROUND(AVG(duration) FILTER (WHERE duration IS NOT NULL)),
        'unique_users', COUNT(DISTINCT user_id),
        'date_range', json_build_object('start', start_date, 'end', end_date)
    ) INTO result
    FROM system_logs 
    WHERE created_at BETWEEN start_date AND end_date;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Örnek log kayıtları (test için)
INSERT INTO system_logs (level, category, message, details, user_email, user_action)
VALUES 
    ('info', 'system', 'Sistem başlatıldı', '{"version": "2.0.0", "environment": "production"}', 'system@mesi.com', 'startup'),
    ('success', 'auth', 'Admin kullanıcısı giriş yaptı', '{"login_method": "email"}', 'admin@mesi.com', 'login'),
    ('info', 'user', 'Yeni kullanıcı kaydedildi', '{"department": "IT", "position": "Developer"}', 'john@mesi.com', 'register'),
    ('warning', 'security', 'Şifre denemesi başarısız', '{"attempts": 3, "ip": "192.168.1.100"}', 'unknown@mesi.com', 'failed_login'),
    ('error', 'system', 'Veritabanı bağlantı hatası', '{"error_code": "DB001", "retry_count": 3}', 'system@mesi.com', 'db_error')
ON CONFLICT DO NOTHING;

-- Log tablosu oluşturma bilgilendirme
DO $$
BEGIN
    RAISE NOTICE '✅ system_logs tablosu başarıyla oluşturuldu';
    RAISE NOTICE '📊 İndeksler ve RLS politikaları eklendi';
    RAISE NOTICE '🧹 Temizleme ve istatistik fonksiyonları hazır';
    RAISE NOTICE '🔐 Sadece admin kullanıcıları loglara erişebilir';
END $$;
