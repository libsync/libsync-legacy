from distutils.core import setup, Extension
import glob

module1 = Extension('connector',
                    define_macros = [('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                    sources = ['connectormodule.c'],
                    library_dirs = ['.libs'],
                    runtime_library_dirs = ['.libs'],
                    extra_objects = ['.libs/libmew.so'],
                    )

setup (name = 'PackageName',
       version = '1.0',
       description = 'This is a demo package',
       author = 'Marcell Vazquez-Chanlatte',
       author_email = 'mvcisback@gmail.com',
       url = 'http://docs.python.org/extending/building',
       long_description = '''
This is really just a demo package.
''',
       data_files=[('/usr/local/lib', glob.glob('*'))],
       ext_modules = [module1])
