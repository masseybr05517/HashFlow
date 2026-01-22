import joblib
import treelite
import treelite.sklearn

rf = joblib.load("randforest_first8.joblib")
tl = treelite.sklearn.import_model(rf)

# Build a shared library you can link/use from C
tl.export_lib(
    libpath="rf_first8.so",
    toolchain="gcc",
    verbose=True
)

print("Built rf_first8.so")
