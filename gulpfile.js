var gulp = require('gulp'),
    connect = require('gulp-connect'),
    clean = require('gulp-clean'),
    cssmin = require('gulp-cssmin'),
    rename = require('gulp-rename'),
    less = require('gulp-less'),
    concat = require('gulp-concat'),
    inject = require('gulp-inject'),
    fs = require('fs'),
    json = JSON.parse(fs.readFileSync('./package.json'));

gulp.task('clean', function () {
  return gulp.src('dist/*')
    .pipe(clean());
});

gulp.task('connect', function(){
    connect.server({
        root: 'dist',
        port: 4000
    });
});

gulp.task('copy-html', ['clean'], function(){
    return gulp.src('app/**/*.html')
            .pipe(gulp.dest('dist'));
});

gulp.task('copy-fonts', ['clean'], function(){
    return gulp.src('static/fonts/**/*')
            .pipe(gulp.dest('dist/fonts'));
});

gulp.task('copy-images', ['clean'], function(){
    return gulp.src('static/images/**/*')
            .pipe(gulp.dest('dist/img'));
});

gulp.task('vendorjs', ['clean'], function(){
    return gulp.src(['vendor/jquery/jquery.min.js', 'vendor/bootstrap/bootstrap.js', 'vendor/angular/angular.js', 'vendor/**/*.js'])
            .pipe(concat('vendor.js'))
            .pipe(gulp.dest('dist/assets'));
});

gulp.task('vendorcss', ['clean'], function(){
    return gulp.src(['vendor/font-awesome/font-awesome.min.css', 'vendor/bootstrap/bootstrap.css', 'vendor/**/*.css'])
            .pipe(concat('vendor.css'))
            .pipe(gulp.dest('dist/assets'));
});

gulp.task('appjsfiles', ['clean'], function(){
    return gulp.src(['app/filters/*.js', 'app/services/*.js', 'app/directives/*.js', 'app/modules/**/*.js', 'app/config/local.js', 'app/config/app.js'])
            .pipe(concat(json.name.toLowerCase() + '.js'))
            .pipe(gulp.dest('dist/assets'));
});

gulp.task('link-files', ['copy-images', 'copy-fonts', 'copy-html', 'vendorjs', 'vendorcss', 'appjsfiles'], function () {
  var target = gulp.src('dist/index.html');
  var sources = gulp.src(['dist/assets/vendor.js', 'dist/assets/*.js', 'dist/assets/vendor.css', 'dist/assets/*.css'], {read: false});

  return target.pipe(inject(sources, {relative: true}))
    .pipe(gulp.dest('dist'));
});

gulp.task('style', ['clean'], function(){
    return gulp.src('app/styles/app.less')
        .pipe(less())
        .pipe(rename(json.name.toLowerCase() + '.css'))
		    .pipe(gulp.dest('dist/assets'))
});

gulp.task('logger', function(){
    console.info('===== A file changed ======== restarting server now ====');
});

gulp.task('watch', function() {
    gulp.watch(['app/**/*', 'vendor/**/*', 'static/**/*'], ['logger', 'style' , 'link-files']);
});

gulp.task('serve', ['connect', 'style', 'watch', 'link-files']);
