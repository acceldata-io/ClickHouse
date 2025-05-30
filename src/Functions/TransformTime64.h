#pragma once

#include <Core/Types.h>
#include <Core/DecimalFunctions.h>

namespace DB
{
/** Transform-type wrapper for DateTime64, simplifies DateTime64 support for given Transform.
 *
 * Depending on what overloads of Transform::execute() are available, when called with DateTime64 value,
 * invokes Transform::execute() with either:
 * * whole part of DateTime64 value, discarding fractional part (1)
 * * DateTime64 value and scale factor (2)
 * * DateTime64 broken down to components, result of execute is then re-assembled back into DateTime64 value (3)
 *
 * Suitable Transform-types are commonly used in Date/DateTime manipulation functions,
 * and should implement static (or const) function with following signatures:
 * 1:
 *     R execute(Int64 whole_value, ... )
 * 2:
 *     R execute(DateTime64 value, Int64 scale_multiplier, ... )
 * 3:
 *     R execute(DecimalUtils::DecimalComponents<DateTime64> components, ... )
 *
 * Where R could be of arbitrary type, in case of (3) if R is DecimalUtils::DecimalComponents<DateTime64>, result is re-assembed back into DateTime64.
*/
template <typename Transform>
class TransformTime64
{
private:
    // Detect if Transform::execute is const or static method
    // with signature defined by template args (ignoring result type).
    template<typename = void, typename... Args>
    struct TransformHasExecuteOverload : std::false_type {};

    template<typename... Args>
    struct TransformHasExecuteOverload<std::void_t<decltype(std::declval<Transform>().execute(std::declval<Args>()...))>, Args...>
        : std::true_type {};

    template<typename... Args>
    static constexpr bool TransformHasExecuteOverload_v = TransformHasExecuteOverload<void, Args...>::value;

public:
    static constexpr auto name = Transform::name;

    // non-explicit constructor to allow creating from scale value (or with no scale at all), indispensable in some contexts.
    TransformTime64(UInt32 scale_) /// NOLINT
        : scale_multiplier(DecimalUtils::scaleMultiplier<Time64::NativeType>(scale_))
    {}

    TransformTime64(Time64::NativeType scale_multiplier_ = 1) /// NOLINT(google-explicit-constructor)
        : scale_multiplier(scale_multiplier_)
    {}

    template <typename ... Args>
    auto NO_SANITIZE_UNDEFINED execute(const Time64 & t, Args && ... args) const
    {
        /// Type conversion from float to integer may be required.
        /// We are Ok with implementation specific result for out of range and denormals conversion.

        if constexpr (TransformHasExecuteOverload_v<Time64, decltype(scale_multiplier), Args...>)
        {
            return wrapped_transform.execute(t, scale_multiplier, std::forward<Args>(args)...);
        }
        else if constexpr (TransformHasExecuteOverload_v<DecimalUtils::DecimalComponents<Time64>, Args...>)
        {
            auto components = DecimalUtils::splitWithScaleMultiplier(t, scale_multiplier);

            const auto result = wrapped_transform.execute(components, std::forward<Args>(args)...);
            using ResultType = std::decay_t<decltype(result)>;

            if constexpr (std::is_same_v<DecimalUtils::DecimalComponents<Time64>, ResultType>)
            {
                return DecimalUtils::decimalFromComponentsWithMultiplier<Time64>(result, scale_multiplier);
            }
            else
            {
                return result;
            }
        }
        else
        {
            auto components = DecimalUtils::splitWithScaleMultiplier(t, scale_multiplier);
            if (t.value < 0 && components.fractional)
                --components.whole;

            return wrapped_transform.execute(static_cast<Int64>(components.whole), std::forward<Args>(args)...);
        }
    }

    template <typename T, typename... Args>
    requires(!std::same_as<T, Time64>)
    auto execute(const T & t, Args &&... args) const
    {
        return wrapped_transform.execute(t, std::forward<Args>(args)...);
    }


    template <typename ... Args>
    auto NO_SANITIZE_UNDEFINED executeExtendedResult(const Time64 & t, Args && ... args) const
    {
        /// Type conversion from float to integer may be required.
        /// We are Ok with implementation specific result for out of range and denormals conversion.

        if constexpr (TransformHasExecuteOverload_v<Time64, decltype(scale_multiplier), Args...>)
        {
            return wrapped_transform.executeExtendedResult(t, scale_multiplier, std::forward<Args>(args)...);
        }
        else if constexpr (TransformHasExecuteOverload_v<DecimalUtils::DecimalComponents<Time64>, Args...>)
        {
            auto components = DecimalUtils::splitWithScaleMultiplier(t, scale_multiplier);

            const auto result = wrapped_transform.executeExtendedResult(components, std::forward<Args>(args)...);
            using ResultType = std::decay_t<decltype(result)>;

            if constexpr (std::is_same_v<DecimalUtils::DecimalComponents<Time64>, ResultType>)
            {
                return DecimalUtils::decimalFromComponentsWithMultiplier<Time64>(result, scale_multiplier);
            }
            else
            {
                return result;
            }
        }
        else
        {
            const auto components = DecimalUtils::splitWithScaleMultiplier(t, scale_multiplier);
            return wrapped_transform.executeExtendedResult(static_cast<Int64>(components.whole), std::forward<Args>(args)...);
        }
    }

    template <typename T, typename ... Args>
    requires (!std::same_as<T, Time64>)
    auto executeExtendedResult(const T & t, Args && ... args) const
    {
        return wrapped_transform.executeExtendedResult(t, std::forward<Args>(args)...);
    }

    Time64::NativeType getScaleMultiplier() const { return scale_multiplier; }

private:
    Time64::NativeType scale_multiplier = 1;
    Transform wrapped_transform = {};
};

}
