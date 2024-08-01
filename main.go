package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/form/v4"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
)

const (
	SESSION_COOKIE = "SESSION_ID"
)

func main() {
	app, err := createApp()
	if err != nil {
		log.Fatalf("Failed to create app: %v\n", err)
		os.Exit(1)
	}
	router, err := createRouter(app)
	if err != nil {
		log.Fatalf("Failed to create router: %v\n", err)
		os.Exit(1)
	}
	run(&http.Server{
		Addr:    ":3000",
		Handler: router,
	})
}

type App struct {
	templates   Templates
	devMode     bool
	formDecoder *form.Decoder
	validate    *validator.Validate
}

func createApp() (*App, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}

	app := &App{}
	app.templates = createTemplates()

	devMode, set := os.LookupEnv("DEV_MODE")
	if set {
		app.devMode = devMode == "1" || strings.ToLower(devMode) == "true"
	} else {
		app.devMode = false
	}

	app.formDecoder = form.NewDecoder()
	app.validate = validator.New(validator.WithRequiredStructEnabled())

	return app, nil
}

func refreshTemplatesMiddleware(app *App) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			app.templates = createTemplates()
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func authOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie(SESSION_COOKIE)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validationErrors(err validator.ValidationErrors) map[string]string {
	errors := make(map[string]string)
	for _, err := range err {
		msg := ""
		if err.Tag() == "required" {
			msg = fmt.Sprintf("%v is required", err.Field())
		} else if err.Tag() == "email" {
			msg = fmt.Sprintf("%v is invalid", err.Field())
		} else if err.Tag() == "min" {
			msg = fmt.Sprintf("%v is too short", err.Field())
		}
		errors[err.Field()] = msg
	}
	return errors
}

func renderDashboard(app *App, w http.ResponseWriter) {
	err := app.templates.dashboard.Execute(w, nil)
	if err != nil {
		log.Printf("Failed to execute template: %v", err)
	}
}

func renderLogin(app *App, w http.ResponseWriter) {
	err := app.templates.login.Execute(w, nil)
	if err != nil {
		log.Printf("Failed to execute template: %v", err)
	}
}

func createRouter(app *App) (chi.Router, error) {
	r := chi.NewRouter()

	r.Use(middleware.Logger)

	if app.devMode {
		r.Use(refreshTemplatesMiddleware(app))
	}

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie(SESSION_COOKIE)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		}
	})

	r.Route("/dashboard", func(r chi.Router) {
		r.Use(authOnly)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			renderDashboard(app, w)
		})
	})

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie(SESSION_COOKIE)
		if err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		renderLogin(app, w)
	})

	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		type Form struct {
			Email    string `form:"email"    validate:"required,email"`
			Password string `form:"password" validate:"required,min=8"`
		}
		var form Form
		err := app.formDecoder.Decode(&form, r.Form)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Failed to decode form values: %v", err)))
			return
		}

		err = app.validate.Struct(form)
		if err != nil {
			errors := validationErrors(err.(validator.ValidationErrors))
			app.templates.login.ExecuteTemplate(w, "login_form_contents", map[string]any{
				"Inputs": form,
				"Errors": errors,
			})
			return
		}

		sessionId := form.Email // TODO: Actual id
		http.SetCookie(w, &http.Cookie{
			Name:     SESSION_COOKIE,
			Path:     "/",
			Value:    sessionId,
			Expires:  time.Now().AddDate(0, 1, 0),
			MaxAge:   60 * 60 * 24 * 30,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   !app.devMode,
		})

		w.Header().Add("Hx-Push-Url", "/dashboard")
		w.Header().Add("Hx-Retarget", "body")
		renderDashboard(app, w)
	})

	r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Cookie(SESSION_COOKIE)
		if err != nil {
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     SESSION_COOKIE,
			Path:     "/",
			Value:    "",
			Expires:  time.Now(),
			MaxAge:   0,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   !app.devMode,
		})

		w.Header().Add("Hx-Push-Url", "/login")
		w.Header().Add("Hx-Retarget", "body")
		renderLogin(app, w)
	})

	workDir, _ := os.Getwd()
	fileServer(r, "/static", http.Dir(filepath.Join(workDir, "static")))

	return r, nil
}

func templateMap(pairs ...any) (map[string]any, error) {
	if len(pairs)%2 != 0 {
		return nil, errors.New("template map function expects key value pairs, but got a non even number of arguments")
	}

	props := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		key := fmt.Sprintf("%v", pairs[i])
		value := pairs[i+1]
		props[key] = value
	}

	return props, nil
}

func templateSlice(values ...any) []any {
	return values
}

type Templates struct {
	dashboard *template.Template
	login     *template.Template
}

func createTemplates() Templates {
	Must := template.Must
	var templates Templates

	AddTemplateWithBase := func(name string, filename string) *template.Template {
		return Must(template.New(name).Funcs(template.FuncMap{
			"Props": templateMap,
			"Map":   templateMap,
			"Slice": templateSlice,
		}).ParseFiles("templates/base.html", filename))
	}

	templates.dashboard = AddTemplateWithBase("dashboard.html", "templates/dashboard.html")
	templates.login = AddTemplateWithBase("login.html", "templates/login.html")
	return templates
}

func fileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("fileServer does not permit any URL parameters.")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	pathPrefix := strings.TrimSuffix(path, "/*")
	fs := http.StripPrefix(pathPrefix, http.FileServer(root))

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
}

func run(server *http.Server) {
	go func() {
		log.Printf("Serving on port %s", server.Addr)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
		log.Println("Stopped serving new connections.")
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownRelease()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("HTTP shutdown error: %v", err)
	}
	log.Println("Graceful shutdown complete.")
}
