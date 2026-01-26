-- Normalize product image_url paths to "images/<filename>"
-- Run this once on your database.

-- 1) Remove leading "/"
UPDATE products
SET image_url = SUBSTRING(image_url, 2)
WHERE image_url LIKE '/%';

-- 2) Remove "static/" prefix
UPDATE products
SET image_url = SUBSTRING(image_url, 8)
WHERE image_url LIKE 'static/%';

-- 3) Remove "static/images/" prefix if present
UPDATE products
SET image_url = SUBSTRING(image_url, 15)
WHERE image_url LIKE 'static/images/%';

-- 4) Ensure all non-URL paths are under "images/"
UPDATE products
SET image_url = CONCAT('images/', image_url)
WHERE image_url IS NOT NULL
  AND image_url NOT LIKE 'images/%'
  AND image_url NOT LIKE 'http%';
