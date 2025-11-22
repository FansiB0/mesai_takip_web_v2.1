-- ========================================
-- USERS Tablosu Düzeltme
-- MESA Takip Sistemi - Role Kolonu Ekleme
-- ========================================

-- Mevcut users tablosunu kontrol et ve role kolonu ekle
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user' 
CHECK (role IN ('admin', 'user'));

-- Eğer tablo tamamen yoksa oluştur
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    start_date DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index'ler
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- RLS (Row Level Security) etkinleştir
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- RLS Politikaları
-- Kullanıcılar kendi verilerini görebilir
CREATE POLICY "Users can view own data" ON users
    FOR SELECT USING (auth.uid() = id);

-- Kullanıcılar kendi verilerini güncelleyebilir
CREATE POLICY "Users can update own data" ON users
    FOR UPDATE USING (auth.uid() = id);

-- Admin'ler tüm verileri görebilir
CREATE POLICY "Admins can view all users" ON users
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM auth.users 
            WHERE auth.users.id = auth.uid() 
            AND auth.users.raw_user_meta_data->>'role' = 'admin'
        )
    );

-- Admin'ler tüm verileri güncelleyebilir
CREATE POLICY "Admins can update all users" ON users
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM auth.users 
            WHERE auth.users.id = auth.uid() 
            AND auth.users.raw_user_meta_data->>'role' = 'admin'
        )
    );

-- Admin'ler yeni kullanıcı ekleyebilir
CREATE POLICY "Admins can insert users" ON users
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1 FROM auth.users 
            WHERE auth.users.id = auth.uid() 
            AND auth.users.raw_user_meta_data->>'role' = 'admin'
        )
    );

-- Trigger: updated_at alanını otomatik güncelle
CREATE OR REPLACE FUNCTION update_users_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_users_updated_at();

-- Test için admin kullanıcısı ekle (isteğe bağlı)
INSERT INTO users (id, email, name, role)
VALUES (
    gen_random_uuid(),
    'admin@mesi.com',
    'Admin User',
    'admin'
) ON CONFLICT (email) DO NOTHING;

-- Bilgilendirme
DO $$
BEGIN
    RAISE NOTICE '✅ users tablosu başarıyla güncellendi';
    RAISE NOTICE '📋 role kolonu eklendi (admin/user)';
    RAISE NOTICE '🔒 RLS politikaları oluşturuldu';
    RAISE NOTICE '🔄 updated_at trigger eklendi';
END $$;
