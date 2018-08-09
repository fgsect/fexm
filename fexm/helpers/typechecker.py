"""
Poor man's runtime typechecker.
"""
__author__ = 'domenukk'
import inspect
from typing import *

from functools import wraps

NoneType = type(None)


class TypeCheckError(ValueError):
    """
    Error class indicating Errors while checking types...
    """

    def __init__(self, message: str, var_name: str, checked_type: Any, actual_type: Any,
                 *args: object, **kwargs: object) -> None:
        """
        An error while type checking
        :param message: The message
        :param var_name: The name of the failed variable
        :param checked_type: The type we demanded
        :param actual_type: The type we actually got
        """
        super().__init__(message, *args, **kwargs)
        self.var_name = var_name
        self.checked_type = checked_type
        self.actual_type = actual_type


def default_val(func: Callable[[Any], Any], argname: str) -> Any:
    argspec = inspect.getfullargspec(func)
    if not argname in argspec.args:
        return None
    diff = len(argspec.args) - len(argspec.defaults)
    arg_index = argspec.args.index(argname) - diff  # We need to count from the diff: args without default are in front.
    return argspec.defaults[arg_index]


def correct_type(vartype: type, expected_type: type) -> bool:
    """
    Checks if the type is correct.
    So far only supports primitive types, classes, Unions and Optionals.
    non-trivial Dicts or Lists are not supported. Scusi.
    :param vartype: type of the variable
    :param expected_type: type to check against
    :return: true if correct, false otherweise.
    """
    # This only works for Union[], and Optional[] or single values. We ignore anything else for now.
    subs = getattr(expected_type, "_subs_tree", lambda: [vartype])  # We get the contents of Unions
    for sub in subs():
        try:
            if issubclass(type(sub), type(Union)):
                # We ignore Unions (for now)
                continue
            if sub == Any and vartype is not NoneType:
                # If we encounter an "Any" type, we just return and feel happy.
                return True
            if sub == Callable or sub == callable and callable(vartype):
                # If we encounter a Callable and, indeed, vartype is callable -> hooray.
                # (Of course, we ignore _what_ is actually been passed to the callable)...
                return True
            if issubclass(vartype, sub):
                # Actual type check.
                return True
        except Exception as ex:
            # Debug stuff.
            print("Error ignored: {}".format(ex))
    return False


def check(var_name: str, var: Any, expected_type: type) -> None:
    """check type of var against expectedType
    and raise a meaningful TypeCheckError on mismatch.
    """
    vartype = type(var)
    if not correct_type(vartype, expected_type):
        raise TypeCheckError("Got wrong type for {var_name}: expected {expected_type} but got {var_type}(value: {var})."
                             .format(var_name=var_name, expected_type=expected_type, var_type=vartype, var=var),
                             var_name, expected_type, vartype)


def checked(func: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """
    Decorator that will check types to a given function at runtime.
    :param func: Function to check types at runtime for.
    :return: The function, but with type checks.
    """

    @wraps(func)
    def decorator(*args: Any, **kwargs: Any) -> Any:
        hints = inspect.signature(func).bind(*args, **kwargs)
        arg_hints = get_type_hints(func)
        ret_hint = arg_hints.pop('return', NoneType)

        for name, hint in arg_hints.items():
            if hint is None:
                hint = NoneType
            argument = hints.arguments.get(name)
            if argument is None and not correct_type(hint, NoneType):
                argument = default_val(func, name)
            check(name, argument, hint)
        ret = func(*args, **kwargs)
        if ret is None:
            return None
        if ret_hint is None:
            ret_hint = NoneType
        check("-return-", ret, ret_hint)
        return ret

    return decorator
