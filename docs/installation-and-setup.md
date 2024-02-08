---
title: Installation & Setup
sidebar_position: 1.2
---

You can install the package via composer:

```bash
composer require javaabu/passport
```

# Publishing the config file

Publishing the config file is optional:

```bash
php artisan vendor:publish --provider="Javaabu\Passport\PassportServiceProvider" --tag="passport-config"
```

This is the default content of the config file:

```php
// TODO
```
