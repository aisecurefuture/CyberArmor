# frozen_string_literal: true

require_relative 'lib/cyberarmor/version'

Gem::Specification.new do |spec|
  spec.name          = 'cyberarmor-sdk'
  spec.version       = CyberArmor::VERSION
  spec.authors       = ['CyberArmor Engineering']
  spec.email         = ['sdk@cyberarmor.ai']

  spec.summary       = 'CyberArmor AI Identity Control Plane SDK for Ruby'
  spec.description   = <<~DESC
    The CyberArmor Ruby SDK integrates your Ruby applications and AI workloads
    with the CyberArmor AI Identity Control Plane. It provides zero-trust policy
    enforcement, audit emission, and drop-in wrappers for popular AI providers
    such as OpenAI and Anthropic.
  DESC

  spec.homepage      = 'https://cyberarmor.ai'
  spec.license       = 'Apache-2.0'

  spec.required_ruby_version = '>= 3.1.0'

  spec.metadata = {
    'homepage_uri'    => spec.homepage,
    'source_code_uri' => 'https://github.com/cyberarmor-io/cyberarmor-sdk-ruby',
    'changelog_uri'   => 'https://github.com/cyberarmor-io/cyberarmor-sdk-ruby/blob/main/CHANGELOG.md',
    'bug_tracker_uri' => 'https://github.com/cyberarmor-io/cyberarmor-sdk-ruby/issues',
    'rubygems_mfa_required' => 'true'
  }

  spec.files = Dir[
    'lib/**/*.rb',
    'README.md',
    'LICENSE',
    'CHANGELOG.md',
    '*.gemspec'
  ]

  spec.bindir        = 'bin'
  spec.executables   = []
  spec.require_paths = ['lib']

  # Runtime dependencies — all are standard library (net/http, openssl, json)
  # No mandatory third-party runtime deps. Provider gems are optional.

  # Optional integrations
  spec.add_development_dependency 'ruby-openai',   '~> 7.0'
  spec.add_development_dependency 'anthropic',      '~> 0.3'

  # Development tooling
  spec.add_development_dependency 'bundler',  '~> 2.4'
  spec.add_development_dependency 'rake',     '~> 13.0'
  spec.add_development_dependency 'rspec',    '~> 3.12'
  spec.add_development_dependency 'webmock',  '~> 3.23'
  spec.add_development_dependency 'rubocop',  '~> 1.64'
end
