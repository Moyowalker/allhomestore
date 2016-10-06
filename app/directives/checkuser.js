angular.module('CheckUser',[])
.directive('checkUser', ['$rootScope', '$location', 'userSrv',
  function ($r, $location, userSrv) {
    return {
      link: function (scope, elem, attrs, ctrl) {
        $r.$on('$routeChangeStart', function(e, curr, prev){
          if (!prev.access.isFree && !userSrv.isLogged) {
            // reload the login route
          }
          /*
          * IMPORTANT:
          * It's not difficult to fool the previous control,
          * so it's really IMPORTANT to repeat server side
          * the same control before sending back reserved data.
          */
        });
      }
    }
  }]);
