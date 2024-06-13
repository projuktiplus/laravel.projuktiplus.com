## লারাভেল Authentication Guards & Providers: একটি পূর্ণাঙ্গ গাইড

লারাভেল ফ্রেমওয়ার্কে অথেনটিকেশন একটি মৌলিক উপাদান। এটির মাধ্যমে ব্যবহারকারীর তথ্য যাচাই করা হয় এবং সুরক্ষিত অ্যাক্সেস প্রদান করা হয়। অথেনটিকেশন সিস্টেমে দুটি গুরুত্বপূর্ণ অংশ রয়েছে: গার্ডস এবং প্রোভাইডার্স। এই পোস্টে, আমরা লারাভেল অথেনটিকেশন গার্ডস এবং প্রোভাইডার্স নিয়ে বিস্তারিত আলোচনা করবো এবং এটির বাস্তব জীবনের ব্যবহার এবং বাস্তবায়ন কৌশল সম্পর্কে জানবো।

### অথেনটিকেশন গার্ডস কি?

গার্ড (Guard) হলো একটি কম্পোনেন্ট যা ইউজারের অথেনটিকেশন রিকোয়েস্ট প্রক্রিয়া করে। গার্ড নির্ধারণ করে কোন ইউজার সেশনে লগইন আছে এবং সেই ইউজার কোন অথেনটিকেশন প্রোভাইডার ব্যবহার করছে। লারাভেলে ডিফল্ট গার্ড হিসেবে `web` এবং `api` ব্যবহার করা হয়। `web` গার্ড সেশন এবং কুকি ভিত্তিক অথেনটিকেশন হ্যান্ডেল করে, আর `api` গার্ড টোকেন ভিত্তিক অথেনটিকেশন হ্যান্ডেল করে।

### অথেনটিকেশন প্রোভাইডার্স কি?

প্রোভাইডার (Provider) হলো অথেনটিকেশন ডেটা রিট্রিভাল লজিক। এটি নির্ধারণ করে কিভাবে ইউজারের তথ্য ডাটাবেজ থেকে বের করা হবে এবং যাচাই করা হবে। সাধারণত, প্রোভাইডার ইউজার মডেল এবং টেবিলের সাথে কাজ করে।

### গার্ডস এবং প্রোভাইডার্স কনফিগারেশন

গার্ডস এবং প্রোভাইডার্স কনফিগারেশন `config/auth.php` ফাইলে থাকে। এখানে আমরা বিভিন্ন গার্ড এবং প্রোভাইডার সেটাপ করতে পারি।

```php
// config/auth.php

return [
    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],

        'api' => [
            'driver' => 'token',
            'provider' => 'users',
            'hash' => false,
        ],
    ],

    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],

        // 'users' => [
        //     'driver' => 'database',
        //     'table' => 'users',
        // ],
    ],

    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_resets',
            'expire' => 60,
            'throttle' => 60,
        ],
    ],
];
```

উপরের কনফিগারেশনে, আমরা `web` এবং `api` গার্ড সেট করেছি। `web` গার্ড সেশন ড্রাইভার ব্যবহার করে এবং `api` গার্ড টোকেন ড্রাইভার ব্যবহার করে। উভয় গার্ডই `users` প্রোভাইডার ব্যবহার করছে যা এলোকোয়েন্ট ড্রাইভার দিয়ে ইউজার মডেলের তথ্য রিট্রিভ করে।

### কাস্টম গার্ড তৈরি করা

আমরা যদি ডিফল্ট গার্ডস এবং প্রোভাইডার্স ছাড়া নতুন গার্ড তৈরি করতে চাই, তাহলে কিভাবে করবো? নিচে একটি উদাহরণ দেওয়া হলো।

```php
// app/Providers/AuthServiceProvider.php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;

class AuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->registerPolicies();

        Auth::extend('custom', function($app, $name, array $config) {
            return new CustomGuard(Auth::createUserProvider($config['provider']));
        });
    }
}
```

এখানে আমরা একটি কাস্টম গার্ড তৈরি করেছি যেটি `CustomGuard` ক্লাস ব্যবহার করে।

```php
// app/Guards/CustomGuard.php

namespace App\Guards;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

class CustomGuard implements Guard
{
    protected $provider;
    protected $user;

    public function __construct(UserProvider $provider)
    {
        $this->provider = $provider;
    }

    public function check()
    {
        return !is_null($this->user());
    }

    public function guest()
    {
        return !$this->check();
    }

    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $id = session('user_id');
        if (!is_null($id)) {
            return $this->user = $this->provider->retrieveById($id);
        }

        return null;
    }

    public function id()
    {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }

        return null;
    }

    public function validate(array $credentials = [])
    {
        if (empty($credentials['username']) || empty($credentials['password'])) {
            return false;
        }

        $user = $this->provider->retrieveByCredentials($credentials);

        if (!is_null($user) && $this->provider->validateCredentials($user, $credentials)) {
            session(['user_id' => $user->getAuthIdentifier()]);
            $this->setUser($user);
            return true;
        }

        return false;
    }

    public function setUser(Authenticatable $user)
    {
        $this->user = $user;

        return $this;
    }
}
```

এখানে আমরা একটি কাস্টম গার্ড তৈরি করেছি যা সেশনের উপর ভিত্তি করে কাজ করে। এখন আমরা `config/auth.php` ফাইলে আমাদের কাস্টম গার্ড রেজিস্টার করবো।

```php
// config/auth.php

return [
    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],

        'api' => [
            'driver' => 'token',
            'provider' => 'users',
            'hash' => false,
        ],

        'custom' => [
            'driver' => 'custom',
            'provider' => 'users',
        ],
    ],
];
```

### প্রোভাইডার কাস্টমাইজেশন

লারাভেল প্রোভাইডার কনফিগারেশনও কাস্টমাইজ করা যায়। ডিফল্টভাবে, লারাভেল `eloquent` এবং `database` প্রোভাইডার প্রদান করে। তবে আমরা চাইলে কাস্টম প্রোভাইডার তৈরি করতে পারি।

```php
// app/Providers/AuthServiceProvider.php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;
use App\Extensions\CustomUserProvider;

class AuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->registerPolicies();

        Auth::provider('custom', function($app, array $config) {
            return new CustomUserProvider($app['hash'], $config['model']);
        });
    }
}
```

এখানে আমরা একটি কাস্টম প্রোভাইডার তৈরি করেছি।

```php
// app/Extensions/CustomUserProvider.php

namespace App\Extensions;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;

class CustomUserProvider extends EloquentUserProvider
{
    public function validateCredentials(UserContract $user, array $credentials)
    {
        // Custom credential validation logic
        return $credentials['password'] === 'secret';
    }
}
```

এখন `config/auth.php` ফাইলে আমাদের কাস্টম প্রোভাইডার রেজিস্টার করবো।

```php
// config/auth.php

return [
    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],

        'api' => [
            'driver' => 'token',
            'provider' => 'users',
            'hash' => false,
        ],

        'custom' => [
            'driver' => 'custom',
            'provider' => 'custom_users',
        ],
    ],

    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],

        'custom_users' => [
            'driver' => 'custom',
            'model' => App\Models\User::class,
        ],
    ],
];
```

### বাস্তব জীবনের ব্যবহার

এখন, আমরা একটি উদাহরণ দেখে নেই যেখানে আমরা আমাদের কাস্টম গার্ড এবং প্রোভাইডার ব্যবহার করবো। 

1. **লগইন কন্ট্রোলার**:

```php
// app/Http/Controllers/Auth/LoginController.php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('username', 'password');

        if (Auth::guard('custom')->attempt($credentials)) {
            return redirect()->intended('dashboard');
        }

        return redirect('login')->with

Errors(['message' => 'Invalid credentials']);
    }
}
```

2. **রাউটস**:

```php
// routes/web.php

use App\Http\Controllers\Auth\LoginController;

Route::get('login', [LoginController::class, 'showLoginForm'])->name('login');
Route::post('login', [LoginController::class, 'login']);
Route::get('dashboard', function () {
    return 'Welcome to your dashboard';
})->middleware('auth:custom');
```

এই পোস্টে, আমরা লারাভেলের অথেনটিকেশন গার্ডস এবং প্রোভাইডার্স নিয়ে বিস্তারিত আলোচনা করেছি। আমরা দেখেছি কিভাবে গার্ড এবং প্রোভাইডার কাজ করে এবং কিভাবে কাস্টম গার্ড ও প্রোভাইডার তৈরি করা যায়। আশা করি, এই পোস্টটি আপনাদের জন্য উপকারী হবে এবং লারাভেলের অথেনটিকেশন সিস্টেম সম্পর্কে আপনার ধারণা বৃদ্ধি করবে।