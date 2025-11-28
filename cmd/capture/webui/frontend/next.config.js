const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
})

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  reactStrictMode: true,
  // Transpile the @dreadl0ck/netcap-ui workspace package to ensure React context is shared
  transpilePackages: ['@dreadl0ck/netcap-ui'],
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  // Target modern browsers only - no legacy polyfills
  compiler: {
    // Remove console.log in production
    removeConsole: process.env.NODE_ENV === 'production',
  },
}

module.exports = withBundleAnalyzer(nextConfig)

