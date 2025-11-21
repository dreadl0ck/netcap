const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
})

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  reactStrictMode: true,
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  // Target modern browsers only - no legacy polyfills
  compiler: {
    // Remove console.log in production
    removeConsole: process.env.NODE_ENV === 'production',
  },
  // Turbopack configuration (Next.js 16+ uses Turbopack by default)
  turbopack: {
    // Turbopack handles modern ES and tree-shaking natively
    // Most webpack optimizations are built into Turbopack
  },
}

module.exports = withBundleAnalyzer(nextConfig)

