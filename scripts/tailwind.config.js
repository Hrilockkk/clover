// Конфиг для статической сборки Tailwind (замена runtime-CDN):
//   npm run build:css
// После правки классов в разметке/JS CSS нужно пересобрать.
module.exports = {
    content: ['frontend/**/*.html', 'frontend/js/**/*.js'],
    theme: { extend: {} },
    plugins: []
};
