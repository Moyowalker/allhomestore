angular.module('app.authService', [])
    .factory('Auth', ['$http', 'LocalService', 'API', '$q', 'AccessLevel',
        function ($http, LocalService, API, $q, AccessLevel) {
            return {
                 authorize: function (access) {
                    if (access === AccessLevel.user) {
                        return this.isAuthenticated();
                    } else {
                        return true;
                    }
                },
                isAuthenticated: function () {
                    return LocalService.get('auth_token');
                },
                login: function (credentials) {
                    var deferred = $q.defer();
                    API.all('login').post(credentials).then(function (data) {
                        LocalService.set('auth_token', JSON.stringify(data));
                        deferred.resolve(data);
                    }, function (error) {
                        deferred.reject(error);
                    });

                    return deferred.promise;
                },
                loginModal: function (credentials) {
                    var deferred = $q.defer();
                    API.all('login').post(credentials).then(function (data) {
                        LocalService.set('auth_token', JSON.stringify(data));
                        deferred.resolve(data);
                    }, function (error) {
                        deferred.reject(error);
                    });

                    return deferred.promise;
                },
                save: function (credentials) {
                    var defer = $q.defer();
                    LocalService.set('auth_token', JSON.stringify(credentials));
                    defer.resolve("");
                    return defer.promise;
                },
                logout: function () {
                    // The backend doesn't care about logouts, delete the token and you're good to go.
                    LocalService.unset('auth_token');
                },
                getUser: function () {
                    if (LocalService.get('auth_token')) {
                        return angular.fromJson(LocalService.get('auth_token')).user;
                    } else {
                        return false;
                    }
                },
                updateUser: function(user) {
                    var current = angular.fromJson(LocalService.get('auth_token'));
                    var update = {token: current.token, user: user}
                    this.save(update)
                }
            }
        }
    ])
    .factory('AuthInterceptor', ['$q', '$injector', 'LocalService','VarService',
        function ($q, $injector, LocalService, VarService) {
            return {
                request: function (config) {
                    var token;
                    if (LocalService.get('auth_token')) {
                        token = angular.fromJson(LocalService.get('auth_token')).token;
                    }
                    if (token) {
                        config.headers.Authorization = 'Bearer ' + token;
                    }
                    return config;
                },
                responseError: function (response) {
                    if (response.status === 401 || response.status === 403) {
                        LocalService.unset('auth_token');
                        var donateInfo = VarService.all();
                        if(donateInfo.length < 1){
                            $injector.get('$state').go('access.login');
                        }
                    }
                    return $q.reject(response);
                }
            }
        }
    ])
    .config(['$httpProvider',
        function ($httpProvider) {
            $httpProvider.interceptors.push('AuthInterceptor');
        }
    ]);
